//! Integer-only descriptors used to schedule the three parity-check bands.

use crate::xof::xof_array;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TileKind {
    Thick,
    Thin,
}

impl TileKind {
    fn as_byte(self) -> u8 {
        match self {
            Self::Thick => 1,
            Self::Thin => 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StructureDescriptor {
    pub index: u16,
    pub tile: TileKind,
    pub orientation: u8,
    pub depth: u8,
    pub lineage: u64,
    pub orchard_x: u16,
    pub orchard_y: u16,
    pub golden_left: u64,
    pub golden_right: u64,
}

impl StructureDescriptor {
    pub(crate) fn encode(self) -> [u8; 36] {
        let mut output = [0_u8; 36];
        output[0..2].copy_from_slice(&self.index.to_le_bytes());
        output[2] = self.tile.as_byte();
        output[3] = self.orientation;
        output[4] = self.depth;
        output[5] = 0;
        output[6..14].copy_from_slice(&self.lineage.to_le_bytes());
        output[14..16].copy_from_slice(&self.orchard_x.to_le_bytes());
        output[16..18].copy_from_slice(&self.orchard_y.to_le_bytes());
        output[18..26].copy_from_slice(&self.golden_left.to_le_bytes());
        output[26..34].copy_from_slice(&self.golden_right.to_le_bytes());
        output[34] = self.golden_left.count_ones() as u8;
        output[35] = self.golden_right.count_ones() as u8;
        output
    }
}

#[derive(Clone, Copy)]
struct InflationNode {
    tile: TileKind,
    depth: u8,
    lineage: u64,
}

pub fn derive_schedule(seed: &[u8; 32], count: usize) -> Vec<StructureDescriptor> {
    if count == 0 {
        return Vec::new();
    }

    let control = xof_array::<16>(b"AperiSyVra/P1/structure-control/v1", &[seed]);
    let mut nodes = inflation_nodes(count);
    let rotation = u16::from_le_bytes([control[0], control[1]]) as usize % nodes.len();
    nodes.rotate_left(rotation);
    if control[2] & 1 == 1 {
        nodes.reverse();
    }

    let orchard_skip = u16::from_le_bytes([control[3], control[4]]) as usize % 64;
    let orchard = primitive_directions(count + orchard_skip)
        .into_iter()
        .skip(orchard_skip);

    let golden_skip = u16::from_le_bytes([control[5], control[6]]) as usize % 89;
    let mut golden = (1_u64, 1_u64);
    for _ in 0..golden_skip {
        golden = (golden.1, golden.0.wrapping_add(golden.1));
    }

    let mirrored = control[7] & 1 == 1;
    let mut orientation = control[8] % 5;

    nodes
        .into_iter()
        .zip(orchard)
        .enumerate()
        .map(|(index, (node, (orchard_x, orchard_y)))| {
            let step = match node.tile {
                TileKind::Thick => 2,
                TileKind::Thin => 1,
            };
            orientation = if mirrored {
                (orientation + 5 - step) % 5
            } else {
                (orientation + step) % 5
            };

            let descriptor = StructureDescriptor {
                index: index as u16,
                tile: node.tile,
                orientation,
                depth: node.depth,
                lineage: node.lineage,
                orchard_x,
                orchard_y,
                golden_left: golden.0,
                golden_right: golden.1,
            };
            golden = (golden.1, golden.0.wrapping_add(golden.1));
            descriptor
        })
        .collect()
}

fn inflation_nodes(count: usize) -> Vec<InflationNode> {
    let mut nodes = vec![InflationNode {
        tile: TileKind::Thick,
        depth: 0,
        lineage: 1,
    }];

    while nodes.len() < count {
        let mut next = Vec::with_capacity(nodes.len().saturating_mul(2));
        for node in nodes {
            let depth = node.depth.saturating_add(1);
            match node.tile {
                TileKind::Thick => {
                    next.push(InflationNode {
                        tile: TileKind::Thick,
                        depth,
                        lineage: node.lineage.wrapping_shl(1),
                    });
                    next.push(InflationNode {
                        tile: TileKind::Thin,
                        depth,
                        lineage: node.lineage.wrapping_shl(1) | 1,
                    });
                }
                TileKind::Thin => next.push(InflationNode {
                    tile: TileKind::Thick,
                    depth,
                    lineage: node.lineage.wrapping_shl(1),
                }),
            }
        }
        nodes = next;
    }
    nodes.truncate(count);
    nodes
}

fn primitive_directions(count: usize) -> Vec<(u16, u16)> {
    let mut directions = Vec::with_capacity(count);
    let mut shell = 1_u16;

    while directions.len() < count {
        for x in 0..=shell {
            let y = shell;
            if gcd(x, y) == 1 {
                directions.push((x, y));
                if directions.len() == count {
                    return directions;
                }
            }
        }
        for y in (0..shell).rev() {
            let x = shell;
            if gcd(x, y) == 1 {
                directions.push((x, y));
                if directions.len() == count {
                    return directions;
                }
            }
        }
        shell = shell.saturating_add(1);
    }
    directions
}

fn gcd(mut left: u16, mut right: u16) -> u16 {
    while right != 0 {
        let remainder = left % right;
        left = right;
        right = remainder;
    }
    left
}

#[cfg(test)]
mod tests {
    use super::{derive_schedule, gcd, TileKind};

    #[test]
    fn schedule_is_deterministic() {
        let seed = [7_u8; 32];
        let first = derive_schedule(&seed, 256);
        let second = derive_schedule(&seed, 256);
        assert_eq!(first, second);
        assert_eq!(first.len(), 256);
        assert!(first.iter().any(|item| item.tile == TileKind::Thick));
        assert!(first.iter().any(|item| item.tile == TileKind::Thin));
        assert!(first
            .iter()
            .all(|item| gcd(item.orchard_x, item.orchard_y) == 1));
    }

    #[test]
    fn different_seeds_change_the_schedule() {
        assert_ne!(
            derive_schedule(&[1_u8; 32], 32),
            derive_schedule(&[2_u8; 32], 32)
        );
    }
}
