use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::parameters::{
    CODE_LENGTH, DECODER_MAX_ROUNDS, ERROR_WEIGHT, HIERARCHY_COLUMN_WEIGHT, HIERARCHY_ROW_END,
    HIERARCHY_ROW_START, LOCAL_COLUMN_WEIGHT, LOCAL_ROW_END, LOCAL_ROW_START,
    ORCHARD_COLUMN_WEIGHT, ORCHARD_ROW_END, ORCHARD_ROW_START, ROW_OPERATION_COUNT,
    SECRET_COLUMN_WEIGHT, SYNDROME_BITS,
};
use crate::structure::{derive_schedule, StructureDescriptor};
use crate::syndrome::Syndrome;
use crate::xof::{xof_into, BlockStream};

const MAX_COLUMN_ATTEMPTS: u32 = 128;

#[derive(Clone, Copy, Debug)]
pub(crate) enum RowOp {
    Swap { left: u16, right: u16 },
    Xor { target: u16, source: u16 },
}

#[derive(Clone, Debug)]
pub(crate) struct TrapdoorMaterial {
    pub(crate) secret_columns: [Syndrome; CODE_LENGTH],
    pub(crate) public_columns: [Syndrome; CODE_LENGTH],
    pub(crate) secret_to_public: [u16; CODE_LENGTH],
    pub(crate) row_ops: Vec<RowOp>,
}

#[derive(Clone, Debug)]
pub(crate) struct DecodeResult {
    pub(crate) positions: Vec<usize>,
    pub(crate) rounds: usize,
}

#[cfg(any(test, feature = "research-tools"))]
#[derive(Clone, Debug)]
pub(crate) struct MatrixReport {
    pub(crate) minimum_row_degree: usize,
    pub(crate) maximum_row_degree: usize,
    pub(crate) average_row_degree: f64,
    pub(crate) maximum_pair_overlap: usize,
    pub(crate) average_public_column_weight: f64,
    pub(crate) public_density: f64,
}

pub(crate) fn derive_trapdoor(seed: &[u8; 32]) -> Result<TrapdoorMaterial> {
    let secret_columns = derive_secret_columns(seed)?;
    let row_ops = derive_row_ops(seed);
    let public_to_secret = derive_permutation(seed);
    let mut secret_to_public = [0_u16; CODE_LENGTH];

    for (public, secret) in public_to_secret.iter().copied().enumerate() {
        secret_to_public[secret as usize] = public as u16;
    }

    let mut public_columns = [Syndrome::ZERO; CODE_LENGTH];
    for (public, secret) in public_to_secret.iter().copied().enumerate() {
        public_columns[public] = apply_forward(secret_columns[secret as usize], &row_ops);
    }

    Ok(TrapdoorMaterial {
        secret_columns,
        public_columns,
        secret_to_public,
        row_ops,
    })
}

fn derive_secret_columns(seed: &[u8; 32]) -> Result<[Syndrome; CODE_LENGTH]> {
    let schedule = derive_schedule(seed, CODE_LENGTH);
    let mut columns = Vec::with_capacity(CODE_LENGTH);
    let mut row_loads = vec![0_u16; SYNDROME_BITS];
    let mut used_pairs = vec![false; SYNDROME_BITS * SYNDROME_BITS];
    let mut seen = HashSet::with_capacity(CODE_LENGTH);

    for descriptor in schedule {
        let mut accepted = None;
        for attempt in 0..MAX_COLUMN_ATTEMPTS {
            let mut rows = Vec::with_capacity(SECRET_COLUMN_WEIGHT);
            select_band_rows(
                seed,
                descriptor,
                attempt,
                b"AperiSyVra/P1/local-rows/v1",
                LOCAL_ROW_START,
                LOCAL_ROW_END,
                LOCAL_COLUMN_WEIGHT,
                &row_loads,
                &used_pairs,
                &mut rows,
            );
            select_band_rows(
                seed,
                descriptor,
                attempt,
                b"AperiSyVra/P1/hierarchy-rows/v1",
                HIERARCHY_ROW_START,
                HIERARCHY_ROW_END,
                HIERARCHY_COLUMN_WEIGHT,
                &row_loads,
                &used_pairs,
                &mut rows,
            );
            select_band_rows(
                seed,
                descriptor,
                attempt,
                b"AperiSyVra/P1/orchard-rows/v1",
                ORCHARD_ROW_START,
                ORCHARD_ROW_END,
                ORCHARD_COLUMN_WEIGHT,
                &row_loads,
                &used_pairs,
                &mut rows,
            );
            rows.sort_unstable();

            let column = Syndrome::from_rows(&rows);
            if column.count_ones() as usize == SECRET_COLUMN_WEIGHT && seen.insert(column.words()) {
                accepted = Some((column, rows));
                break;
            }
        }

        let (column, rows) = accepted.ok_or(Error::KeyGenerationFailed)?;
        for row in &rows {
            row_loads[*row] = row_loads[*row].saturating_add(1);
        }
        for left in 0..rows.len() {
            for right in (left + 1)..rows.len() {
                let index = pair_index(rows[left], rows[right]);
                used_pairs[index] = true;
            }
        }
        columns.push(column);
    }

    columns.try_into().map_err(|_| Error::KeyGenerationFailed)
}

#[allow(clippy::too_many_arguments)]
fn select_band_rows(
    seed: &[u8; 32],
    descriptor: StructureDescriptor,
    attempt: u32,
    domain: &'static [u8],
    start: usize,
    end: usize,
    count: usize,
    row_loads: &[u16],
    used_pairs: &[bool],
    selected: &mut Vec<usize>,
) {
    let descriptor_bytes = descriptor.encode();
    let attempt_bytes = attempt.to_le_bytes();
    let mut score_bytes = vec![0_u8; (end - start) * 2];
    xof_into(
        domain,
        &[seed, &descriptor_bytes, &attempt_bytes],
        &mut score_bytes,
    );

    for _ in 0..count {
        let mut best_row = None;
        let mut best_key = None;

        for row in start..end {
            if selected.contains(&row) {
                continue;
            }
            let conflicts = selected
                .iter()
                .filter(|other| used_pairs[pair_index(row, **other)])
                .count();
            let offset = (row - start) * 2;
            let score = u16::from_le_bytes([score_bytes[offset], score_bytes[offset + 1]]);
            let key = (conflicts, row_loads[row] as usize, score as usize, row);
            let replace = match best_key {
                Some(current) => key < current,
                None => true,
            };
            if replace {
                best_key = Some(key);
                best_row = Some(row);
            }
        }

        selected.push(best_row.expect("non-empty parity-check band"));
    }
}

fn pair_index(left: usize, right: usize) -> usize {
    let (low, high) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    low * SYNDROME_BITS + high
}

fn derive_row_ops(seed: &[u8; 32]) -> Vec<RowOp> {
    let mut stream = BlockStream::new(b"AperiSyVra/P1/row-mixing/v1", seed, &[]);
    let mut operations = Vec::with_capacity(ROW_OPERATION_COUNT);

    for index in 0..ROW_OPERATION_COUNT {
        let left = stream.uniform(SYNDROME_BITS) as u16;
        let mut right = stream.uniform(SYNDROME_BITS) as u16;
        while right == left {
            right = stream.uniform(SYNDROME_BITS) as u16;
        }

        if index % 5 == 0 {
            operations.push(RowOp::Swap { left, right });
        } else {
            operations.push(RowOp::Xor {
                target: left,
                source: right,
            });
        }
    }
    operations
}

fn derive_permutation(seed: &[u8; 32]) -> [u16; CODE_LENGTH] {
    let mut permutation: Vec<u16> = (0..CODE_LENGTH as u16).collect();
    let mut stream = BlockStream::new(b"AperiSyVra/P1/coordinate-permutation/v1", seed, &[]);

    for index in (1..CODE_LENGTH).rev() {
        let swap_with = stream.uniform(index + 1);
        permutation.swap(index, swap_with);
    }

    permutation
        .try_into()
        .expect("fixed-size coordinate permutation")
}

pub(crate) fn apply_forward(mut value: Syndrome, operations: &[RowOp]) -> Syndrome {
    for operation in operations {
        value = apply_operation(value, *operation);
    }
    value
}

pub(crate) fn apply_reverse(mut value: Syndrome, operations: &[RowOp]) -> Syndrome {
    for operation in operations.iter().rev() {
        value = apply_operation(value, *operation);
    }
    value
}

fn apply_operation(mut value: Syndrome, operation: RowOp) -> Syndrome {
    match operation {
        RowOp::Swap { left, right } => {
            let left = left as usize;
            let right = right as usize;
            if value.get(left) != value.get(right) {
                value.toggle(left);
                value.toggle(right);
            }
        }
        RowOp::Xor { target, source } => {
            if value.get(source as usize) {
                value.toggle(target as usize);
            }
        }
    }
    value
}

pub(crate) fn decode_secret(
    columns: &[Syndrome; CODE_LENGTH],
    syndrome: Syndrome,
) -> Option<DecodeResult> {
    decode_with_threshold_offset(columns, syndrome, 1)
        .or_else(|| decode_with_threshold_offset(columns, syndrome, 0))
}

fn decode_with_threshold_offset(
    columns: &[Syndrome; CODE_LENGTH],
    syndrome: Syndrome,
    threshold_offset: usize,
) -> Option<DecodeResult> {
    let mut residual = syndrome;
    let mut estimate = [false; CODE_LENGTH];

    for round in 0..DECODER_MAX_ROUNDS {
        if residual.is_zero() {
            let positions = estimate
                .iter()
                .enumerate()
                .filter_map(|(index, bit)| bit.then_some(index))
                .collect::<Vec<_>>();
            return (positions.len() == ERROR_WEIGHT).then_some(DecodeResult {
                positions,
                rounds: round,
            });
        }

        let scores = columns
            .iter()
            .map(|column| column.and_count(residual) as usize)
            .collect::<Vec<_>>();
        let maximum = scores.iter().copied().max().unwrap_or(0);
        let threshold =
            (SECRET_COLUMN_WEIGHT / 2 + 1).max(maximum.saturating_sub(threshold_offset));
        let candidates = scores
            .iter()
            .enumerate()
            .filter_map(|(index, score)| (*score >= threshold).then_some(index))
            .collect::<Vec<_>>();

        if candidates.is_empty() {
            return None;
        }

        for index in candidates {
            estimate[index] = !estimate[index];
            residual ^= columns[index];
        }
    }

    if residual.is_zero() {
        let positions = estimate
            .iter()
            .enumerate()
            .filter_map(|(index, bit)| bit.then_some(index))
            .collect::<Vec<_>>();
        (positions.len() == ERROR_WEIGHT).then_some(DecodeResult {
            positions,
            rounds: DECODER_MAX_ROUNDS,
        })
    } else {
        None
    }
}

#[cfg(any(test, feature = "research-tools"))]
pub(crate) fn matrix_report(material: &TrapdoorMaterial) -> MatrixReport {
    let mut row_degrees = vec![0_usize; SYNDROME_BITS];
    for column in &material.secret_columns {
        for (row, degree) in row_degrees.iter_mut().enumerate() {
            if column.get(row) {
                *degree += 1;
            }
        }
    }

    let mut maximum_pair_overlap = 0_usize;
    for left in 0..CODE_LENGTH {
        for right in (left + 1)..CODE_LENGTH {
            maximum_pair_overlap = maximum_pair_overlap.max(
                material.secret_columns[left].and_count(material.secret_columns[right]) as usize,
            );
        }
    }

    let public_weight = material
        .public_columns
        .iter()
        .map(|column| column.count_ones() as usize)
        .sum::<usize>();
    let average_public_column_weight = public_weight as f64 / CODE_LENGTH as f64;

    MatrixReport {
        minimum_row_degree: *row_degrees.iter().min().unwrap_or(&0),
        maximum_row_degree: *row_degrees.iter().max().unwrap_or(&0),
        average_row_degree: row_degrees.iter().sum::<usize>() as f64 / SYNDROME_BITS as f64,
        maximum_pair_overlap,
        average_public_column_weight,
        public_density: average_public_column_weight / SYNDROME_BITS as f64,
    }
}

#[cfg(test)]
mod tests {
    use super::{apply_forward, apply_reverse, decode_secret, derive_trapdoor, matrix_report};
    use crate::parameters::{CODE_LENGTH, ERROR_WEIGHT, SECRET_COLUMN_WEIGHT};
    use crate::syndrome::Syndrome;

    #[test]
    fn row_mixing_round_trips() {
        let material = derive_trapdoor(&[9_u8; 32]).expect("derive trapdoor");
        let value = Syndrome::from_rows(&[0, 1, 63, 64, 127, 128, 191]);
        assert_eq!(
            apply_reverse(apply_forward(value, &material.row_ops), &material.row_ops),
            value
        );
    }

    #[test]
    fn matrix_has_expected_shape() {
        let material = derive_trapdoor(&[3_u8; 32]).expect("derive trapdoor");
        assert!(material
            .secret_columns
            .iter()
            .all(|column| column.count_ones() as usize == SECRET_COLUMN_WEIGHT));
        let report = matrix_report(&material);
        assert!(report.minimum_row_degree > 0);
        assert!(report.maximum_pair_overlap <= 2);
        assert!(report.public_density > 0.30);
        assert!(report.public_density < 0.70);
    }

    #[test]
    fn decoder_recovers_known_error() {
        let material = derive_trapdoor(&[5_u8; 32]).expect("derive trapdoor");
        let positions = [0, 7, 29, 41, 88, 119, 151, 190, 222, 255];
        assert_eq!(positions.len(), ERROR_WEIGHT);
        let mut syndrome = Syndrome::ZERO;
        for position in positions {
            syndrome ^= material.secret_columns[position];
        }
        let decoded = decode_secret(&material.secret_columns, syndrome).expect("decode error");
        assert_eq!(decoded.positions, positions);
        assert!(decoded.rounds < 10);
        assert_eq!(material.secret_columns.len(), CODE_LENGTH);
    }
}
