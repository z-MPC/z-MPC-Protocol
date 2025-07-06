//! z-MPC: Laurent Series based One-Round Secret Sharing with ZK-Proof
//! 
//! This library provides a distributed signing engine based on Laurent Series
//! with zero-knowledge proof verification for secure secret reconstruction.
//! 
//! ## Features
//! - Aggregator-free secure reconstruction
//! - Lagrange-free structure reducing computational complexity
//! - Pedersen Commitment + ZK Proof based validity verification
//! - Multi-curve support (secp256k1, P-256, Edwards25519)
//! - CLI and WebAssembly ready Rust engine
//! - Distributed network communication

pub mod curve;
pub mod laurent;
pub mod pedersen;
pub mod zkp;
pub mod error;
pub mod types;
pub mod network;

pub use error::{Error, Result};
pub use types::*;

// Re-export main components for easy access
pub use curve::{Curve, Scalar, Point};
pub use laurent::{LaurentSeries, Share};
pub use pedersen::PedersenCommitment;
pub use zkp::ZeroKnowledgeProof;
pub use network::{NetworkNode, NetworkCoordinator, NetworkMessage, Participant};

/// Initialize the z-MPC library
pub fn init() -> Result<()> {
    tracing_subscriber::fmt::init();
    tracing::info!("z-MPC library initialized");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_init() {
        assert!(init().is_ok());
    }
} 