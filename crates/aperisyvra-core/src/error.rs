use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid AperiSyVra format: {0}")]
    InvalidFormat(&'static str),

    #[error("unsupported AperiSyVra parameter set")]
    UnsupportedParameters,

    #[error("failed to generate the hidden parity-check matrix")]
    KeyGenerationFailed,

    #[error("message authentication failed")]
    AuthenticationFailed,

    #[error("input exceeds the P1 limit")]
    LimitExceeded,
}

pub type Result<T> = std::result::Result<T, Error>;
