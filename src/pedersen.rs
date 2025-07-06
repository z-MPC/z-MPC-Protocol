//! Pedersen Commitment for share validation
//! 
//! This module implements Pedersen commitments for the b_{-1,i} shares:
//! C_i = g^{b_{-1,i}} * h^{r_i}
//! 
//! Provides commitment generation and verification for trustless reconstruction.

use crate::{Error, Result, CurveType, Randomness, Commitment};
use crate::curve::{Curve, Scalar, Point, create_curve};
use crate::laurent::Share;
use serde::{Deserialize, Serialize};
use rand::Rng;

/// Pedersen Commitment parameters
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PedersenCommitment {
    pub curve_type: CurveType,
    pub g: Point,  // Generator point
    pub h: Point,  // Random generator point
}

impl PedersenCommitment {
    /// Create new Pedersen commitment scheme
    pub fn new(curve_type: CurveType) -> Result<Self> {
        let curve = create_curve(curve_type);
        let g = curve.generator();
        
        // Generate random generator h
        let h_scalar = curve.random_scalar()?;
        let h = g.mul(&h_scalar)?;
        
        Ok(Self {
            curve_type,
            g,
            h,
        })
    }
    
    /// Create commitment for a share value
    pub fn commit(&self, value: &Scalar, randomness: &Randomness) -> Result<Commitment> {
        let curve = create_curve(self.curve_type);
        let r = curve.scalar_from_bytes(randomness)?;
        
        // C = g^value * h^r
        let g_value = self.g.mul(value)?;
        let h_r = self.h.mul(&r)?;
        let commitment_point = g_value.add(&h_r)?;
        
        Ok(commitment_point.to_compressed_bytes()?)
    }
    
    /// Create commitment for a share
    pub fn commit_share(&self, share: &Share) -> Result<Commitment> {
        let curve = create_curve(self.curve_type);
        let value = curve.scalar_from_bytes(&share.value)?;
        
        // Generate random randomness
        let mut rng = rand::thread_rng();
        let randomness: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        
        self.commit(&value, &randomness)
    }
    
    /// Verify commitment
    pub fn verify(&self, commitment: &Commitment, value: &Scalar, randomness: &Randomness) -> Result<bool> {
        let curve = create_curve(self.curve_type);
        let r = curve.scalar_from_bytes(randomness)?;
        
        // Recompute commitment
        let g_value = self.g.mul(value)?;
        let h_r = self.h.mul(&r)?;
        let computed_commitment = g_value.add(&h_r)?;
        let computed_bytes = computed_commitment.to_compressed_bytes()?;
        
        Ok(commitment == &computed_bytes)
    }
    
    /// Verify share commitment
    pub fn verify_share_commitment(&self, share: &Share, commitment: &Commitment, randomness: &Randomness) -> Result<bool> {
        let curve = create_curve(self.curve_type);
        let value = curve.scalar_from_bytes(&share.value)?;
        
        self.verify(commitment, &value, randomness)
    }
    
    /// Generate random randomness for commitment
    pub fn generate_randomness(&self) -> Randomness {
        let mut rng = rand::thread_rng();
        (0..32).map(|_| rng.gen()).collect()
    }
    
    /// Get commitment parameters
    pub fn get_parameters(&self) -> (Point, Point) {
        (self.g.clone(), self.h.clone())
    }
    
    /// Create commitment with known randomness
    pub fn commit_with_randomness(&self, value: &Scalar, randomness: &Randomness) -> Result<Commitment> {
        self.commit(value, randomness)
    }
    
    /// Batch commit multiple values
    pub fn batch_commit(&self, values: &[Scalar], randomness: &[Randomness]) -> Result<Vec<Commitment>> {
        if values.len() != randomness.len() {
            return Err(Error::InvalidInput("Values and randomness must have same length".to_string()));
        }
        
        let mut commitments = Vec::new();
        for (value, rand) in values.iter().zip(randomness.iter()) {
            commitments.push(self.commit(value, rand)?);
        }
        
        Ok(commitments)
    }
    
    /// Batch verify multiple commitments
    pub fn batch_verify(&self, commitments: &[Commitment], values: &[Scalar], randomness: &[Randomness]) -> Result<bool> {
        if commitments.len() != values.len() || values.len() != randomness.len() {
            return Err(Error::InvalidInput("All arrays must have same length".to_string()));
        }
        
        for (commitment, value, rand) in commitments.iter().zip(values.iter()).zip(randomness.iter()) {
            if !self.verify(commitment, value, rand)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

/// Commitment proof for zero-knowledge verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentProof {
    pub commitment: Commitment,
    pub randomness: Randomness,
    pub curve_type: CurveType,
}

impl CommitmentProof {
    /// Create new commitment proof
    pub fn new(commitment: Commitment, randomness: Randomness, curve_type: CurveType) -> Self {
        Self {
            commitment,
            randomness,
            curve_type,
        }
    }
    
    /// Verify the proof
    pub fn verify(&self, value: &Scalar) -> Result<bool> {
        let pedersen = PedersenCommitment::new(self.curve_type)?;
        pedersen.verify(&self.commitment, value, &self.randomness)
    }
    
    /// Get commitment bytes
    pub fn commitment_bytes(&self) -> &[u8] {
        &self.commitment
    }
    
    /// Get randomness bytes
    pub fn randomness_bytes(&self) -> &[u8] {
        &self.randomness
    }
}

/// Extended share with commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommittedShare {
    pub share: Share,
    pub commitment: Commitment,
    pub randomness: Randomness,
    pub proof: Option<CommitmentProof>,
}

impl CommittedShare {
    /// Create new committed share
    pub fn new(share: Share, commitment: Commitment, randomness: Randomness) -> Self {
        Self {
            share,
            commitment,
            randomness,
            proof: None,
        }
    }
    
    /// Add zero-knowledge proof
    pub fn with_proof(mut self, proof: CommitmentProof) -> Self {
        self.proof = Some(proof);
        self
    }
    
    /// Verify the committed share
    pub fn verify(&self, curve_type: CurveType) -> Result<bool> {
        let pedersen = PedersenCommitment::new(curve_type)?;
        pedersen.verify_share_commitment(&self.share, &self.commitment, &self.randomness)
    }
    
    /// Get the underlying share
    pub fn share(&self) -> &Share {
        &self.share
    }
    
    /// Get commitment
    pub fn commitment(&self) -> &Commitment {
        &self.commitment
    }
}

/// Utility functions for Pedersen commitments
pub mod utils {
    use super::*;
    
    /// Create commitments for all shares
    pub fn commit_all_shares(shares: &[Share], curve_type: CurveType) -> Result<Vec<CommittedShare>> {
        let pedersen = PedersenCommitment::new(curve_type)?;
        let mut committed_shares = Vec::new();
        
        for share in shares {
            let randomness = pedersen.generate_randomness();
            let commitment = pedersen.commit_share(share)?;
            
            committed_shares.push(CommittedShare::new(
                share.clone(),
                commitment,
                randomness,
            ));
        }
        
        Ok(committed_shares)
    }
    
    /// Verify all committed shares
    pub fn verify_all_committed_shares(committed_shares: &[CommittedShare], curve_type: CurveType) -> Result<bool> {
        for committed_share in committed_shares {
            if !committed_share.verify(curve_type)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Generate commitment parameters for a curve
    pub fn generate_parameters(curve_type: CurveType) -> Result<PedersenCommitment> {
        PedersenCommitment::new(curve_type)
    }
} 