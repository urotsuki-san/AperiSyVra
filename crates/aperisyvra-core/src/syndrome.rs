use std::ops::{BitXor, BitXorAssign};

use crate::error::{Error, Result};
use crate::parameters::{SYNDROME_BITS, SYNDROME_BYTES, SYNDROME_WORDS};

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Syndrome([u64; SYNDROME_WORDS]);

impl Syndrome {
    pub const ZERO: Self = Self([0_u64; SYNDROME_WORDS]);

    pub fn from_rows(rows: &[usize]) -> Self {
        let mut value = Self::ZERO;
        for row in rows {
            value.toggle(*row);
        }
        value
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SYNDROME_BYTES {
            return Err(Error::InvalidFormat("unexpected syndrome length"));
        }
        let mut words = [0_u64; SYNDROME_WORDS];
        for (index, word) in words.iter_mut().enumerate() {
            let offset = index * 8;
            *word = u64::from_le_bytes(
                bytes[offset..offset + 8]
                    .try_into()
                    .expect("fixed syndrome word"),
            );
        }
        Ok(Self(words))
    }

    pub fn to_bytes(self) -> [u8; SYNDROME_BYTES] {
        let mut output = [0_u8; SYNDROME_BYTES];
        for (index, word) in self.0.iter().enumerate() {
            let offset = index * 8;
            output[offset..offset + 8].copy_from_slice(&word.to_le_bytes());
        }
        output
    }

    pub fn get(self, bit: usize) -> bool {
        debug_assert!(bit < SYNDROME_BITS);
        ((self.0[bit / 64] >> (bit % 64)) & 1) == 1
    }

    pub fn toggle(&mut self, bit: usize) {
        debug_assert!(bit < SYNDROME_BITS);
        self.0[bit / 64] ^= 1_u64 << (bit % 64);
    }

    pub fn is_zero(self) -> bool {
        self.0.iter().all(|word| *word == 0)
    }

    pub fn count_ones(self) -> u32 {
        self.0.iter().map(|word| word.count_ones()).sum()
    }

    pub fn and_count(self, other: Self) -> u32 {
        self.0
            .iter()
            .zip(other.0.iter())
            .map(|(left, right)| (left & right).count_ones())
            .sum()
    }

    pub(crate) fn words(self) -> [u64; SYNDROME_WORDS] {
        self.0
    }
}

impl BitXor for Syndrome {
    type Output = Self;

    fn bitxor(mut self, rhs: Self) -> Self::Output {
        self ^= rhs;
        self
    }
}

impl BitXorAssign for Syndrome {
    fn bitxor_assign(&mut self, rhs: Self) {
        for (left, right) in self.0.iter_mut().zip(rhs.0.iter()) {
            *left ^= right;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::Syndrome;

    #[test]
    fn byte_round_trip() {
        let value = Syndrome::from_rows(&[0, 63, 64, 127, 128, 191]);
        assert_eq!(
            Syndrome::from_bytes(&value.to_bytes()).expect("parse syndrome"),
            value
        );
        assert_eq!(value.count_ones(), 6);
    }
}
