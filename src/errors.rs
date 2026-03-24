use thiserror::Error;

#[derive(Debug, Error)]
pub enum DpfError {
    #[error("length mismatch: expected {expected}, got {got}")]
    LengthMismatch { expected: usize, got: usize },

    #[error("invalid domain depth: n must be >= 1, got {0}")]
    InvalidDomainDepth(usize),

    #[error("malformed correction word")]
    MalformedCorrectionWord,

    #[error("oracle failure: {0}")]
    OracleFailure(&'static str),
}

pub type Result<T> = std::result::Result<T, DpfError>;
