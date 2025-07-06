use crate::{Error, Result, CurveType};
use crate::curve::{Curve, Scalar, Point};
use p256::{Secp256r1 as P256Curve, Scalar as P256Scalar, ProjectivePoint, AffinePoint};
use p256::elliptic_curve::group::Group;
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand::Rng;

/// P-256 curve implementation
pub struct P256;

impl P256 {
    /// Create new P-256 instance
    pub fn new() -> Self {
        Self
    }
    
    /// Add two scalars
    pub fn add_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = P256Scalar::from_bytes_be(&a.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        let b_scalar = P256Scalar::from_bytes_be(&b.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = a_scalar + b_scalar;
        Ok(Scalar::new(CurveType::P256, result.to_bytes_be().to_vec()))
    }
    
    /// Multiply two scalars
    pub fn mul_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = P256Scalar::from_bytes_be(&a.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        let b_scalar = P256Scalar::from_bytes_be(&b.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = a_scalar * b_scalar;
        Ok(Scalar::new(CurveType::P256, result.to_bytes_be().to_vec()))
    }
    
    /// Invert scalar
    pub fn invert_scalar(s: &Scalar) -> Result<Scalar> {
        let scalar = P256Scalar::from_bytes_be(&s.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = scalar.invert().unwrap_or(P256Scalar::ZERO);
        Ok(Scalar::new(CurveType::P256, result.to_bytes_be().to_vec()))
    }
    
    /// Convert point to compressed bytes
    pub fn point_to_compressed(p: &Point) -> Result<Vec<u8>> {
        let affine = AffinePoint::from_compressed_bytes(&p.x)
            .map_err(|_| Error::CurveError("Invalid point".to_string()))?;
        
        Ok(affine.to_encoded_point(true).as_bytes().to_vec())
    }
    
    /// Create point from compressed bytes
    pub fn point_from_compressed(bytes: &[u8]) -> Result<Point> {
        let affine = AffinePoint::from_compressed_bytes(bytes)
            .map_err(|_| Error::CurveError("Invalid compressed point".to_string()))?;
        
        let encoded = affine.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::P256,
                    x.to_vec(),
                    y.to_vec(),
                ))
            }
            _ => Err(Error::CurveError("Expected uncompressed coordinates".to_string())),
        }
    }
    
    /// Add two points
    pub fn add_points(a: &Point, b: &Point) -> Result<Point> {
        let a_affine = AffinePoint::from_compressed_bytes(&a.x)
            .map_err(|_| Error::CurveError("Invalid point A".to_string()))?;
        let b_affine = AffinePoint::from_compressed_bytes(&b.x)
            .map_err(|_| Error::CurveError("Invalid point B".to_string()))?;
        
        let result = (a_affine + b_affine).to_affine();
        let encoded = result.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::P256,
                    x.to_vec(),
                    y.to_vec(),
                ))
            }
            _ => Err(Error::CurveError("Expected uncompressed coordinates".to_string())),
        }
    }
    
    /// Multiply point by scalar
    pub fn mul_point_scalar(p: &Point, s: &Scalar) -> Result<Point> {
        let point = AffinePoint::from_compressed_bytes(&p.x)
            .map_err(|_| Error::CurveError("Invalid point".to_string()))?;
        let scalar = P256Scalar::from_bytes_be(&s.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar".to_string()))?;
        
        let result = (point * scalar).to_affine();
        let encoded = result.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::P256,
                    x.to_vec(),
                    y.to_vec(),
                ))
            }
            _ => Err(Error::CurveError("Expected uncompressed coordinates".to_string())),
        }
    }
}

impl Curve for P256 {
    fn curve_type(&self) -> CurveType {
        CurveType::P256
    }
    
    fn random_scalar(&self) -> Result<Scalar> {
        let mut rng = rand::thread_rng();
        let scalar = P256Scalar::random(&mut rng);
        Ok(Scalar::new(CurveType::P256, scalar.to_bytes_be().to_vec()))
    }
    
    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<Scalar> {
        let scalar = P256Scalar::from_bytes_be(bytes.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        Ok(Scalar::new(CurveType::P256, scalar.to_bytes_be().to_vec()))
    }
    
    fn scalar_from_u64(&self, value: u64) -> Result<Scalar> {
        let scalar = P256Scalar::from(value);
        Ok(Scalar::new(CurveType::P256, scalar.to_bytes_be().to_vec()))
    }
    
    fn generator(&self) -> Point {
        let generator = ProjectivePoint::generator().to_affine();
        let encoded = generator.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            p256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Point::new(CurveType::P256, x.to_vec(), y.to_vec())
            }
            _ => unreachable!("Generator should have uncompressed coordinates"),
        }
    }
    
    fn point_from_bytes(&self, bytes: &[u8]) -> Result<Point> {
        Self::point_from_compressed(bytes)
    }
    
    fn order(&self) -> Scalar {
        // P-256 order
        let order_bytes = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
            0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51
        ];
        Scalar::new(CurveType::P256, order_bytes.to_vec())
    }
    
    fn field_modulus(&self) -> Scalar {
        // P-256 field modulus
        let modulus_bytes = [
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01
        ];
        Scalar::new(CurveType::P256, modulus_bytes.to_vec())
    }
} 