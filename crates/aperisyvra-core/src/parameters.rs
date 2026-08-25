//! Fixed parameters for the P1 research profile.

pub const PROFILE_NAME: &str = "AperiSyVra-AHC-N256/R192/W10-P1";

pub const CODE_LENGTH: usize = 256;
pub const SYNDROME_BITS: usize = 192;
pub const SYNDROME_WORDS: usize = 3;
pub const SYNDROME_BYTES: usize = SYNDROME_WORDS * 8;
pub const ERROR_WEIGHT: usize = 10;
pub const SECRET_COLUMN_WEIGHT: usize = 7;

pub const LOCAL_ROW_START: usize = 0;
pub const LOCAL_ROW_END: usize = 96;
pub const LOCAL_COLUMN_WEIGHT: usize = 4;

pub const HIERARCHY_ROW_START: usize = LOCAL_ROW_END;
pub const HIERARCHY_ROW_END: usize = 160;
pub const HIERARCHY_COLUMN_WEIGHT: usize = 2;

pub const ORCHARD_ROW_START: usize = HIERARCHY_ROW_END;
pub const ORCHARD_ROW_END: usize = SYNDROME_BITS;
pub const ORCHARD_COLUMN_WEIGHT: usize = 1;

pub const ROW_OPERATION_COUNT: usize = SYNDROME_BITS * 8;
pub const DECODER_MAX_ROUNDS: usize = 32;

pub const SHARED_SECRET_BYTES: usize = 32;
pub const SECRET_SEED_BYTES: usize = 32;
pub const PUBLIC_KEY_ID_BYTES: usize = 16;
pub const MESSAGE_NONCE_BYTES: usize = 24;
pub const MESSAGE_TAG_BYTES: usize = 32;
pub const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

pub const PUBLIC_KEY_BYTES: usize = 32 + CODE_LENGTH * SYNDROME_BYTES;
pub const SECRET_KEY_BYTES: usize = 44;
pub const CIPHERTEXT_BYTES: usize = 28 + SYNDROME_BYTES;
pub const SEALED_HEADER_BYTES: usize = 84 + MESSAGE_TAG_BYTES;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Parameters {
    pub code_length: usize,
    pub syndrome_bits: usize,
    pub error_weight: usize,
    pub secret_column_weight: usize,
    pub decoder_rounds: usize,
}

impl Parameters {
    pub const P1: Self = Self {
        code_length: CODE_LENGTH,
        syndrome_bits: SYNDROME_BITS,
        error_weight: ERROR_WEIGHT,
        secret_column_weight: SECRET_COLUMN_WEIGHT,
        decoder_rounds: DECODER_MAX_ROUNDS,
    };
}
