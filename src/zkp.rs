//! Zero-Knowledge Proof for commitment validity
//! 
//! This module implements Schnorr-style proofs for Pedersen commitments:
//! Prove ∃x,r: C_i = g^x * h^r
//! 
//! Uses Fiat-Shamir heuristic for non-interactive proofs.

use crate::{Error, Result, CurveType, ZKProof};
use crate::curve::{Curve, Scalar, Point, create_curve};
use crate::pedersen::{PedersenCommitment, CommitmentProof};
use crate::laurent::Share;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use rand::Rng;

/// Zero-Knowledge Proof for Pedersen commitment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZeroKnowledgeProof {
    pub curve_type: CurveType,
    pub commitment: Vec<u8>,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
    pub public_point: Vec<u8>,
}

impl ZeroKnowledgeProof {
    /// Create new zero-knowledge proof
    pub fn new(curve_type: CurveType) -> Self {
        Self {
            curve_type,
            commitment: Vec::new(),
            challenge: Vec::new(),
            response: Vec::new(),
            public_point: Vec::new(),
        }
    }
    
    /// Generate proof for a commitment
    pub fn prove(&mut self, pedersen: &PedersenCommitment, value: &Scalar, randomness: &[u8]) -> Result<()> {
        let curve = create_curve(self.curve_type);
        
        // Generate random witness
        let mut rng = rand::thread_rng();
        let alpha = curve.random_scalar()?;
        let beta = curve.random_scalar()?;
        
        // Compute commitment
        let commitment = pedersen.commit(value, randomness)?;
        self.commitment = commitment.clone();
        
        // Compute public point: A = g^alpha * h^beta
        let g_alpha = pedersen.g.mul(&alpha)?;
        let h_beta = pedersen.h.mul(&beta)?;
        let public_point = g_alpha.add(&h_beta)?;
        self.public_point = public_point.to_compressed_bytes()?;
        
        // Generate challenge using Fiat-Shamir heuristic
        let challenge_input = self.create_challenge_input(&commitment, &self.public_point)?;
        let challenge = self.hash_to_scalar(&challenge_input, &curve)?;
        self.challenge = challenge.as_bytes().to_vec();
        
        // Compute response: s1 = alpha + c*x, s2 = beta + c*r
        let c = curve.scalar_from_bytes(&self.challenge)?;
        let c_x = c.mul(value)?;
        let s1 = alpha.add(&c_x)?;
        
        let r = curve.scalar_from_bytes(randomness)?;
        let c_r = c.mul(&r)?;
        let s2 = beta.add(&c_r)?;
        
        // Combine responses
        let mut response = Vec::new();
        response.extend_from_slice(&s1.as_bytes());
        response.extend_from_slice(&s2.as_bytes());
        self.response = response;
        
        Ok(())
    }
    
    /// Verify zero-knowledge proof
    pub fn verify(&self, pedersen: &PedersenCommitment) -> Result<bool> {
        let curve = create_curve(self.curve_type);
        
        // Parse response
        if self.response.len() < 64 {
            return Err(Error::ZKProofError("Invalid response length".to_string()));
        }
        
        let s1_bytes = &self.response[..32];
        let s2_bytes = &self.response[32..64];
        
        let s1 = curve.scalar_from_bytes(s1_bytes)?;
        let s2 = curve.scalar_from_bytes(s2_bytes)?;
        let c = curve.scalar_from_bytes(&self.challenge)?;
        
        // Recompute public point: A' = g^s1 * h^s2 * C^(-c)
        let g_s1 = pedersen.g.mul(&s1)?;
        let h_s2 = pedersen.h.mul(&s2)?;
        let temp = g_s1.add(&h_s2)?;
        
        let commitment_point = Point::from_compressed_bytes(self.curve_type, &self.commitment)?;
        let c_neg = c.invert()?;
        let commitment_c = commitment_point.mul(&c_neg)?;
        let computed_public = temp.add(&commitment_c)?;
        
        let computed_bytes = computed_public.to_compressed_bytes()?;
        
        Ok(computed_bytes == self.public_point)
    }
    
    /// Create challenge input for Fiat-Shamir
    fn create_challenge_input(&self, commitment: &[u8], public_point: &[u8]) -> Result<Vec<u8>> {
        let mut input = Vec::new();
        input.extend_from_slice(b"z-mpc-zkp");
        input.extend_from_slice(&self.curve_type.to_string().as_bytes());
        input.extend_from_slice(commitment);
        input.extend_from_slice(public_point);
        Ok(input)
    }
    
    /// Hash input to scalar for challenge
    fn hash_to_scalar(&self, input: &[u8], curve: &Box<dyn Curve>) -> Result<Scalar> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        
        curve.scalar_from_bytes(&hash.to_vec())
    }
    
    /// Generate proof for a share
    pub fn prove_share(&mut self, pedersen: &PedersenCommitment, share: &Share, randomness: &[u8]) -> Result<()> {
        let curve = create_curve(self.curve_type);
        let value = curve.scalar_from_bytes(&share.value)?;
        self.prove(pedersen, &value, randomness)
    }
    
    /// Get proof as bytes
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(Error::from)
    }
    
    /// Create proof from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).map_err(Error::from)
    }
    
    /// Get commitment from proof
    pub fn commitment(&self) -> &[u8] {
        &self.commitment
    }
    
    /// Get challenge from proof
    pub fn challenge(&self) -> &[u8] {
        &self.challenge
    }
    
    /// Get response from proof
    pub fn response(&self) -> &[u8] {
        &self.response
    }
}

/// Schnorr signature using zero-knowledge proof
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchnorrSignature {
    pub curve_type: CurveType,
    pub challenge: Vec<u8>,
    pub response: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl SchnorrSignature {
    /// Create new Schnorr signature
    pub fn new(curve_type: CurveType) -> Self {
        Self {
            curve_type,
            challenge: Vec::new(),
            response: Vec::new(),
            public_key: Vec::new(),
        }
    }
    
    /// Sign a message using private key
    pub fn sign(&mut self, message: &[u8], private_key: &Scalar) -> Result<()> {
        let curve = create_curve(self.curve_type);
        
        // Generate random k
        let mut rng = rand::thread_rng();
        let k = curve.random_scalar()?;
        
        // Compute R = k*G
        let g = curve.generator();
        let r_point = g.mul(&k)?;
        let r_bytes = r_point.to_compressed_bytes()?;
        
        // Compute public key P = private_key*G
        let public_key = g.mul(private_key)?;
        self.public_key = public_key.to_compressed_bytes()?;
        
        // Create challenge
        let challenge_input = self.create_schnorr_challenge_input(&r_bytes, &self.public_key, message)?;
        let challenge = self.hash_to_scalar(&challenge_input, &curve)?;
        self.challenge = challenge.as_bytes().to_vec();
        
        // Compute response: s = k + c*private_key
        let c = curve.scalar_from_bytes(&self.challenge)?;
        let c_sk = c.mul(private_key)?;
        let s = k.add(&c_sk)?;
        self.response = s.as_bytes().to_vec();
        
        Ok(())
    }
    
    /// Verify Schnorr signature
    pub fn verify(&self, message: &[u8]) -> Result<bool> {
        let curve = create_curve(self.curve_type);
        
        let s = curve.scalar_from_bytes(&self.response)?;
        let c = curve.scalar_from_bytes(&self.challenge)?;
        
        let g = curve.generator();
        let public_key = Point::from_compressed_bytes(self.curve_type, &self.public_key)?;
        
        // Compute R' = s*G - c*P
        let s_g = g.mul(&s)?;
        let c_p = public_key.mul(&c)?;
        let c_neg = c.invert()?;
        let c_neg_p = public_key.mul(&c_neg)?;
        let r_prime = s_g.add(&c_neg_p)?;
        let r_prime_bytes = r_prime.to_compressed_bytes()?;
        
        // Recompute challenge
        let challenge_input = self.create_schnorr_challenge_input(&r_prime_bytes, &self.public_key, message)?;
        let computed_challenge = self.hash_to_scalar(&challenge_input, &curve)?;
        let computed_bytes = computed_challenge.as_bytes().to_vec();
        
        Ok(computed_bytes == self.challenge)
    }
    
    /// Create challenge input for Schnorr signature
    fn create_schnorr_challenge_input(&self, r: &[u8], public_key: &[u8], message: &[u8]) -> Result<Vec<u8>> {
        let mut input = Vec::new();
        input.extend_from_slice(b"z-mpc-schnorr");
        input.extend_from_slice(&self.curve_type.to_string().as_bytes());
        input.extend_from_slice(r);
        input.extend_from_slice(public_key);
        input.extend_from_slice(message);
        Ok(input)
    }
    
    /// Hash input to scalar for challenge
    fn hash_to_scalar(&self, input: &[u8], curve: &Box<dyn Curve>) -> Result<Scalar> {
        let mut hasher = Sha256::new();
        hasher.update(input);
        let hash = hasher.finalize();
        
        curve.scalar_from_bytes(&hash.to_vec())
    }
}

/// Utility functions for zero-knowledge proofs
pub mod utils {
    use super::*;
    
    /// Generate proof for a committed share
    pub fn prove_committed_share(
        pedersen: &PedersenCommitment,
        share: &Share,
        randomness: &[u8],
        curve_type: CurveType,
    ) -> Result<ZeroKnowledgeProof> {
        let mut proof = ZeroKnowledgeProof::new(curve_type);
        proof.prove_share(pedersen, share, randomness)?;
        Ok(proof)
    }
    
    /// Verify proof for a committed share
    pub fn verify_committed_share_proof(
        proof: &ZeroKnowledgeProof,
        pedersen: &PedersenCommitment,
    ) -> Result<bool> {
        proof.verify(pedersen)
    }
    
    /// Generate Schnorr signature for a message
    pub fn sign_message(
        message: &[u8],
        private_key: &Scalar,
        curve_type: CurveType,
    ) -> Result<SchnorrSignature> {
        let mut signature = SchnorrSignature::new(curve_type);
        signature.sign(message, private_key)?;
        Ok(signature)
    }
    
    /// Verify Schnorr signature
    pub fn verify_signature(signature: &SchnorrSignature, message: &[u8]) -> Result<bool> {
        signature.verify(message)
    }
    
    /// Batch verify multiple proofs
    pub fn batch_verify_proofs(
        proofs: &[ZeroKnowledgeProof],
        pedersen: &PedersenCommitment,
    ) -> Result<bool> {
        for proof in proofs {
            if !proof.verify(pedersen)? {
                return Ok(false);
            }
        }
        Ok(true)
    }
} 