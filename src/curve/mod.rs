//! Elliptic curve operations module
//! 
//! Provides unified interface for different elliptic curves:
//! - secp256k1 (Bitcoin/Ethereum)
//! - P-256 (NIST)
//! - Edwards25519

mod secp256k1;
mod p256;
mod ed25519;

use crate::{Error, Result, CurveType};
use serde::{Deserialize, Serialize};

/// Common trait for elliptic curve operations
pub trait Curve: Send + Sync {
    /// Get the curve type
    fn curve_type(&self) -> CurveType;
    
    /// Generate a random scalar
    fn random_scalar(&self) -> Result<Scalar>;
    
    /// Create scalar from bytes
    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<Scalar>;
    
    /// Create scalar from integer
    fn scalar_from_u64(&self, value: u64) -> Result<Scalar>;
    
    /// Get generator point
    fn generator(&self) -> Point;
    
    /// Create point from bytes
    fn point_from_bytes(&self, bytes: &[u8]) -> Result<Point>;
    
    /// Get curve order
    fn order(&self) -> Scalar;
    
    /// Get field modulus
    fn field_modulus(&self) -> Scalar;
}

/// Scalar value on elliptic curve
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scalar {
    pub curve_type: CurveType,
    pub value: Vec<u8>,
}

impl Scalar {
    /// Create new scalar
    pub fn new(curve_type: CurveType, value: Vec<u8>) -> Self {
        Self { curve_type, value }
    }
    
    /// Get scalar as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.value
    }
    
    /// Add two scalars
    pub fn add(&self, other: &Scalar) -> Result<Scalar> {
        if self.curve_type != other.curve_type {
            return Err(Error::CurveError("Cannot add scalars from different curves".to_string()));
        }
        
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::add_scalars(self, other),
            CurveType::P256 => p256::P256::add_scalars(self, other),
            CurveType::Edwards25519 => ed25519::Ed25519::add_scalars(self, other),
        }
    }
    
    /// Multiply two scalars
    pub fn mul(&self, other: &Scalar) -> Result<Scalar> {
        if self.curve_type != other.curve_type {
            return Err(Error::CurveError("Cannot multiply scalars from different curves".to_string()));
        }
        
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::mul_scalars(self, other),
            CurveType::P256 => p256::P256::mul_scalars(self, other),
            CurveType::Edwards25519 => ed25519::Ed25519::mul_scalars(self, other),
        }
    }
    
    /// Invert scalar
    pub fn invert(&self) -> Result<Scalar> {
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::invert_scalar(self),
            CurveType::P256 => p256::P256::invert_scalar(self),
            CurveType::Edwards25519 => ed25519::Ed25519::invert_scalar(self),
        }
    }
}

/// Point on elliptic curve
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Point {
    pub curve_type: CurveType,
    pub x: Vec<u8>,
    pub y: Vec<u8>,
}

impl Point {
    /// Create new point
    pub fn new(curve_type: CurveType, x: Vec<u8>, y: Vec<u8>) -> Self {
        Self { curve_type, x, y }
    }
    
    /// Get point as compressed bytes
    pub fn to_compressed_bytes(&self) -> Result<Vec<u8>> {
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::point_to_compressed(self),
            CurveType::P256 => p256::P256::point_to_compressed(self),
            CurveType::Edwards25519 => ed25519::Ed25519::point_to_compressed(self),
        }
    }
    
    /// Create point from compressed bytes
    pub fn from_compressed_bytes(curve_type: CurveType, bytes: &[u8]) -> Result<Point> {
        match curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::point_from_compressed(bytes),
            CurveType::P256 => p256::P256::point_from_compressed(bytes),
            CurveType::Edwards25519 => ed25519::Ed25519::point_from_compressed(bytes),
        }
    }
    
    /// Add two points
    pub fn add(&self, other: &Point) -> Result<Point> {
        if self.curve_type != other.curve_type {
            return Err(Error::CurveError("Cannot add points from different curves".to_string()));
        }
        
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::add_points(self, other),
            CurveType::P256 => p256::P256::add_points(self, other),
            CurveType::Edwards25519 => ed25519::Ed25519::add_points(self, other),
        }
    }
    
    /// Multiply point by scalar
    pub fn mul(&self, scalar: &Scalar) -> Result<Point> {
        if self.curve_type != scalar.curve_type {
            return Err(Error::CurveError("Cannot multiply point by scalar from different curve".to_string()));
        }
        
        match self.curve_type {
            CurveType::Secp256k1 => secp256k1::Secp256k1::mul_point_scalar(self, scalar),
            CurveType::P256 => p256::P256::mul_point_scalar(self, scalar),
            CurveType::Edwards25519 => ed25519::Ed25519::mul_point_scalar(self, scalar),
        }
    }
}

/// Create curve instance by type
pub fn create_curve(curve_type: CurveType) -> Box<dyn Curve> {
    match curve_type {
        CurveType::Secp256k1 => Box::new(secp256k1::Secp256k1::new()),
        CurveType::P256 => Box::new(p256::P256::new()),
        CurveType::Edwards25519 => Box::new(ed25519::Ed25519::new()),
    }
}

// Re-export specific curve implementations
pub use secp256k1::Secp256k1;
pub use p256::P256;
pub use ed25519::Ed25519; 