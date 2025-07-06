use crate::{Error, Result, CurveType};
use crate::curve::{Curve, Scalar, Point};
use curve25519_dalek::{EdwardsPoint, Scalar as Ed25519Scalar, constants::ED25519_BASEPOINT_POINT};
use curve25519_dalek::edwards::CompressedEdwardsY;
use rand::Rng;

/// Edwards25519 curve implementation
pub struct Ed25519;

impl Ed25519 {
    /// Create new Ed25519 instance
    pub fn new() -> Self {
        Self
    }
    
    /// Add two scalars
    pub fn add_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = Ed25519Scalar::from_bytes_mod_order(&a.value);
        let b_scalar = Ed25519Scalar::from_bytes_mod_order(&b.value);
        
        let result = a_scalar + b_scalar;
        Ok(Scalar::new(CurveType::Edwards25519, result.to_bytes().to_vec()))
    }
    
    /// Multiply two scalars
    pub fn mul_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = Ed25519Scalar::from_bytes_mod_order(&a.value);
        let b_scalar = Ed25519Scalar::from_bytes_mod_order(&b.value);
        
        let result = a_scalar * b_scalar;
        Ok(Scalar::new(CurveType::Edwards25519, result.to_bytes().to_vec()))
    }
    
    /// Invert scalar
    pub fn invert_scalar(s: &Scalar) -> Result<Scalar> {
        let scalar = Ed25519Scalar::from_bytes_mod_order(&s.value);
        let result = scalar.invert();
        Ok(Scalar::new(CurveType::Edwards25519, result.to_bytes().to_vec()))
    }
    
    /// Convert point to compressed bytes
    pub fn point_to_compressed(p: &Point) -> Result<Vec<u8>> {
        let compressed = CompressedEdwardsY::from_slice(&p.x)
            .map_err(|_| Error::CurveError("Invalid point".to_string()))?;
        Ok(compressed.as_bytes().to_vec())
    }
    
    /// Create point from compressed bytes
    pub fn point_from_compressed(bytes: &[u8]) -> Result<Point> {
        let compressed = CompressedEdwardsY::from_slice(bytes)
            .map_err(|_| Error::CurveError("Invalid compressed point".to_string()))?;
        
        let point = compressed.decompress()
            .ok_or_else(|| Error::CurveError("Invalid compressed point".to_string()))?;
        
        Ok(Point::new(
            CurveType::Edwards25519,
            point.x.to_bytes().to_vec(),
            point.y.to_bytes().to_vec(),
        ))
    }
    
    /// Add two points
    pub fn add_points(a: &Point, b: &Point) -> Result<Point> {
        let a_point = Self::bytes_to_edwards_point(&a.x)?;
        let b_point = Self::bytes_to_edwards_point(&b.x)?;
        
        let result = a_point + b_point;
        Ok(Point::new(
            CurveType::Edwards25519,
            result.x.to_bytes().to_vec(),
            result.y.to_bytes().to_vec(),
        ))
    }
    
    /// Multiply point by scalar
    pub fn mul_point_scalar(p: &Point, s: &Scalar) -> Result<Point> {
        let point = Self::bytes_to_edwards_point(&p.x)?;
        let scalar = Ed25519Scalar::from_bytes_mod_order(&s.value);
        
        let result = point * scalar;
        Ok(Point::new(
            CurveType::Edwards25519,
            result.x.to_bytes().to_vec(),
            result.y.to_bytes().to_vec(),
        ))
    }
    
    /// Convert bytes to Edwards point
    fn bytes_to_edwards_point(bytes: &[u8]) -> Result<EdwardsPoint> {
        let compressed = CompressedEdwardsY::from_slice(bytes)
            .map_err(|_| Error::CurveError("Invalid point bytes".to_string()))?;
        
        compressed.decompress()
            .ok_or_else(|| Error::CurveError("Invalid point".to_string()))
    }
}

impl Curve for Ed25519 {
    fn curve_type(&self) -> CurveType {
        CurveType::Edwards25519
    }
    
    fn random_scalar(&self) -> Result<Scalar> {
        let mut rng = rand::thread_rng();
        let scalar = Ed25519Scalar::random(&mut rng);
        Ok(Scalar::new(CurveType::Edwards25519, scalar.to_bytes().to_vec()))
    }
    
    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<Scalar> {
        let scalar = Ed25519Scalar::from_bytes_mod_order(bytes);
        Ok(Scalar::new(CurveType::Edwards25519, scalar.to_bytes().to_vec()))
    }
    
    fn scalar_from_u64(&self, value: u64) -> Result<Scalar> {
        let scalar = Ed25519Scalar::from(value);
        Ok(Scalar::new(CurveType::Edwards25519, scalar.to_bytes().to_vec()))
    }
    
    fn generator(&self) -> Point {
        let generator = ED25519_BASEPOINT_POINT;
        Point::new(
            CurveType::Edwards25519,
            generator.x.to_bytes().to_vec(),
            generator.y.to_bytes().to_vec(),
        )
    }
    
    fn point_from_bytes(&self, bytes: &[u8]) -> Result<Point> {
        Self::point_from_compressed(bytes)
    }
    
    fn order(&self) -> Scalar {
        // Ed25519 order (2^252 + 27742317777372353535851937790883648493)
        let order_bytes = [
            0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x14, 0xde, 0xf9, 0xde, 0xa2, 0xf7, 0x9c, 0xd6,
            0x58, 0x12, 0x63, 0x1a, 0x5c, 0xf5, 0xd3, 0xed
        ];
        Scalar::new(CurveType::Edwards25519, order_bytes.to_vec())
    }
    
    fn field_modulus(&self) -> Scalar {
        // Ed25519 field modulus (2^255 - 19)
        let modulus_bytes = [
            0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xed
        ];
        Scalar::new(CurveType::Edwards25519, modulus_bytes.to_vec())
    }
} 