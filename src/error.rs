use thiserror::Error;

/// Custom error types for z-MPC
#[derive(Error, Debug)]
pub enum Error {
    #[error("Curve operation failed: {0}")]
    CurveError(String),

    #[error("Laurent series operation failed: {0}")]
    LaurentError(String),

    #[error("Pedersen commitment failed: {0}")]
    CommitmentError(String),

    #[error("Zero-knowledge proof failed: {0}")]
    ZKProofError(String),

    #[error("Serialization failed: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Insufficient shares: required {required}, got {got}")]
    InsufficientShares { required: usize, got: usize },

    #[error("Invalid curve type: {0}")]
    InvalidCurve(String),

    #[error("Internal error: {0}")]
    Internal(String),
}

/// Result type for z-MPC operations
pub type Result<T> = std::result::Result<T, Error>;

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Internal(err.to_string())
    }
}

impl From<Box<dyn std::error::Error + Send + Sync>> for Error {
    fn from(err: Box<dyn std::error::Error + Send + Sync>) -> Self {
        Error::Internal(err.to_string())
    }
} 