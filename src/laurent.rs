//! Laurent Series based One-Round Secret Sharing
//! 
//! This module implements the core Laurent Series structure for z-MPC:
//! - f(z) = A(z) + B(z) where sk = b_{-1}
//! - Share structure: f_i(z) = A(z) + B_i(z)
//! - B(z) = Σb_{-k}, sk = Σb_{-1,i}
//! - Linear combine & residue extraction

use crate::{Error, Result, CurveType, ShareId, Threshold, ParticipantCount};
use crate::curve::{Curve, Scalar, Point, create_curve};
use crate::types::{LaurentCoefficients, SharingParams, ReconstructionResult};
use serde::{Deserialize, Serialize};
use rand::Rng;

/// Laurent Series for secret sharing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LaurentSeries {
    pub curve_type: CurveType,
    pub a_coeffs: Vec<Scalar>,  // A(z) coefficients
    pub b_coeffs: Vec<Scalar>,  // B(z) coefficients
    pub threshold: Threshold,
    pub participants: ParticipantCount,
}

impl LaurentSeries {
    /// Create new Laurent series for secret sharing
    pub fn new(params: &SharingParams) -> Result<Self> {
        let curve = create_curve(params.curve_type);
        
        // Generate random coefficients for A(z) and B(z)
        let mut a_coeffs = Vec::new();
        let mut b_coeffs = Vec::new();
        
        // A(z) has coefficients from a_0 to a_{threshold-1}
        for _ in 0..params.threshold {
            a_coeffs.push(curve.random_scalar()?);
        }
        
        // B(z) has coefficients from b_{-threshold} to b_{-1}
        for _ in 0..params.threshold {
            b_coeffs.push(curve.random_scalar()?);
        }
        
        Ok(Self {
            curve_type: params.curve_type,
            a_coeffs,
            b_coeffs,
            threshold: params.threshold,
            participants: params.participants,
        })
    }
    
    /// Generate shares for participants
    pub fn generate_shares(&self) -> Result<Vec<Share>> {
        let curve = create_curve(self.curve_type);
        let mut shares = Vec::new();
        
        for i in 1..=self.participants {
            let share = self.generate_share_for_participant(i as ShareId, &curve)?;
            shares.push(share);
        }
        
        Ok(shares)
    }
    
    /// Generate share for specific participant
    fn generate_share_for_participant(&self, id: ShareId, curve: &Box<dyn Curve>) -> Result<Share> {
        let z = curve.scalar_from_u64(id as u64)?;
        let mut share_value = curve.scalar_from_u64(0)?; // Start with zero
        
        // Compute A(z) = Σ a_k * z^k
        for (k, a_k) in self.a_coeffs.iter().enumerate() {
            let z_k = self.power_scalar(&z, k as u64, curve)?;
            let term = a_k.mul(&z_k)?;
            share_value = share_value.add(&term)?;
        }
        
        // Compute B_i(z) = Σ b_{-k} * z^{-k} for this participant
        for (k, b_neg_k) in self.b_coeffs.iter().enumerate() {
            let z_neg_k = self.power_scalar(&z, -(k as i64 + 1), curve)?;
            let term = b_neg_k.mul(&z_neg_k)?;
            share_value = share_value.add(&term)?;
        }
        
        Ok(Share {
            id,
            value: share_value.as_bytes().to_vec(),
            commitment: None,
            proof: None,
        })
    }
    
    /// Compute scalar power (including negative powers)
    fn power_scalar(&self, base: &Scalar, exponent: i64, curve: &Box<dyn Curve>) -> Result<Scalar> {
        if exponent >= 0 {
            self.positive_power_scalar(base, exponent as u64, curve)
        } else {
            let positive_power = self.positive_power_scalar(base, (-exponent) as u64, curve)?;
            positive_power.invert()
        }
    }
    
    /// Compute positive power of scalar
    fn positive_power_scalar(&self, base: &Scalar, exponent: u64, curve: &Box<dyn Curve>) -> Result<Scalar> {
        if exponent == 0 {
            return curve.scalar_from_u64(1);
        }
        
        let mut result = base.clone();
        for _ in 1..exponent {
            result = result.mul(base)?;
        }
        
        Ok(result)
    }
    
    /// Extract secret from shares using residue extraction
    pub fn reconstruct_secret(&self, shares: &[Share]) -> Result<ReconstructionResult> {
        if shares.len() < self.threshold {
            return Err(Error::InsufficientShares {
                required: self.threshold,
                got: shares.len(),
            });
        }
        
        let curve = create_curve(self.curve_type);
        let mut secret = curve.scalar_from_u64(0)?;
        let mut participants_used = Vec::new();
        
        // Linear combination of shares to extract b_{-1} (the secret)
        for share in shares.iter().take(self.threshold) {
            let share_scalar = curve.scalar_from_bytes(&share.value)?;
            secret = secret.add(&share_scalar)?;
            participants_used.push(share.id);
        }
        
        // The secret is the sum of b_{-1,i} values
        Ok(ReconstructionResult {
            secret: secret.as_bytes().to_vec(),
            valid: true,
            participants_used,
        })
    }
    
    /// Get the secret key (b_{-1})
    pub fn get_secret_key(&self) -> Result<Scalar> {
        let curve = create_curve(self.curve_type);
        let mut secret = curve.scalar_from_u64(0)?;
        
        // Sum all b_{-1} coefficients
        for b_coeff in &self.b_coeffs {
            secret = secret.add(b_coeff)?;
        }
        
        Ok(secret)
    }
    
    /// Get coefficients for verification
    pub fn get_coefficients(&self) -> LaurentCoefficients {
        LaurentCoefficients {
            a_coeffs: self.a_coeffs.iter().map(|s| s.as_bytes().to_vec()).collect(),
            b_coeffs: self.b_coeffs.iter().map(|s| s.as_bytes().to_vec()).collect(),
        }
    }
    
    /// Verify share consistency
    pub fn verify_share(&self, share: &Share) -> Result<bool> {
        let curve = create_curve(self.curve_type);
        let expected_share = self.generate_share_for_participant(share.id, &curve)?;
        
        Ok(share.value == expected_share.value)
    }
}

/// Share with additional metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Share {
    pub id: ShareId,
    pub value: Vec<u8>,
    pub commitment: Option<Vec<u8>>,
    pub proof: Option<Vec<u8>>,
}

impl Share {
    /// Create new share
    pub fn new(id: ShareId, value: Vec<u8>) -> Self {
        Self {
            id,
            value,
            commitment: None,
            proof: None,
        }
    }
    
    /// Add commitment to share
    pub fn with_commitment(mut self, commitment: Vec<u8>) -> Self {
        self.commitment = Some(commitment);
        self
    }
    
    /// Add proof to share
    pub fn with_proof(mut self, proof: Vec<u8>) -> Self {
        self.proof = Some(proof);
        self
    }
    
    /// Get share value as scalar
    pub fn as_scalar(&self, curve_type: CurveType) -> Result<Scalar> {
        let curve = create_curve(curve_type);
        curve.scalar_from_bytes(&self.value)
    }
}

/// Utility functions for Laurent series operations
pub mod utils {
    use super::*;
    
    /// Generate random Laurent series parameters
    pub fn random_params(curve_type: CurveType) -> SharingParams {
        let mut rng = rand::thread_rng();
        let threshold = rng.gen_range(2..=10);
        let participants = rng.gen_range(threshold..=20);
        
        SharingParams {
            curve_type,
            threshold,
            participants,
        }
    }
    
    /// Validate sharing parameters
    pub fn validate_params(params: &SharingParams) -> Result<()> {
        if params.threshold < 2 {
            return Err(Error::InvalidInput("Threshold must be at least 2".to_string()));
        }
        
        if params.participants < params.threshold {
            return Err(Error::InvalidInput("Participants must be at least threshold".to_string()));
        }
        
        Ok(())
    }
} 