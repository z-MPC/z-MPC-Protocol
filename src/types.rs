use serde::{Deserialize, Serialize};

/// Supported elliptic curve types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CurveType {
    /// Bitcoin/Ethereum curve (secp256k1)
    Secp256k1,
    /// NIST P-256 curve
    P256,
    /// Edwards25519 curve
    Edwards25519,
}

impl std::str::FromStr for CurveType {
    type Err = crate::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "k1" | "secp256k1" => Ok(CurveType::Secp256k1),
            "r1" | "p256" => Ok(CurveType::P256),
            "ed25519" | "edwards25519" => Ok(CurveType::Edwards25519),
            _ => Err(crate::Error::InvalidCurve(s.to_string())),
        }
    }
}

impl std::fmt::Display for CurveType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CurveType::Secp256k1 => write!(f, "secp256k1"),
            CurveType::P256 => write!(f, "p256"),
            CurveType::Edwards25519 => write!(f, "ed25519"),
        }
    }
}

/// Share identifier
pub type ShareId = u32;

/// Threshold for secret sharing
pub type Threshold = usize;

/// Number of participants
pub type ParticipantCount = usize;

/// Randomness for commitments
pub type Randomness = Vec<u8>;

/// Commitment value
pub type Commitment = Vec<u8>;

/// Zero-knowledge proof
pub type ZKProof = Vec<u8>;

/// Share data structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: ShareId,
    pub value: Vec<u8>,
    pub commitment: Option<Commitment>,
    pub proof: Option<ZKProof>,
}

/// Laurent series coefficients
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaurentCoefficients {
    pub a_coeffs: Vec<Vec<u8>>,  // A(z) coefficients
    pub b_coeffs: Vec<Vec<u8>>,  // B(z) coefficients
}

/// Secret sharing parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharingParams {
    pub curve_type: CurveType,
    pub threshold: Threshold,
    pub participants: ParticipantCount,
}

/// Reconstruction result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconstructionResult {
    pub secret: Vec<u8>,
    pub valid: bool,
    pub participants_used: Vec<ShareId>,
} 