use crate::{Error, Result, CurveType};
use crate::curve::{Curve, Scalar, Point};
use k256::{Secp256k1 as K256Secp256k1, Scalar as K256Scalar, ProjectivePoint, AffinePoint};
use k256::elliptic_curve::group::Group;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use rand::Rng;

/// secp256k1 curve implementation
pub struct Secp256k1;

impl Secp256k1 {
    /// Create new secp256k1 instance
    pub fn new() -> Self {
        Self
    }
    
    /// Add two scalars
    pub fn add_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = K256Scalar::from_bytes_be(&a.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        let b_scalar = K256Scalar::from_bytes_be(&b.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = a_scalar + b_scalar;
        Ok(Scalar::new(CurveType::Secp256k1, result.to_bytes_be().to_vec()))
    }
    
    /// Multiply two scalars
    pub fn mul_scalars(a: &Scalar, b: &Scalar) -> Result<Scalar> {
        let a_scalar = K256Scalar::from_bytes_be(&a.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        let b_scalar = K256Scalar::from_bytes_be(&b.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = a_scalar * b_scalar;
        Ok(Scalar::new(CurveType::Secp256k1, result.to_bytes_be().to_vec()))
    }
    
    /// Invert scalar
    pub fn invert_scalar(s: &Scalar) -> Result<Scalar> {
        let scalar = K256Scalar::from_bytes_be(&s.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        
        let result = scalar.invert().unwrap_or(K256Scalar::ZERO);
        Ok(Scalar::new(CurveType::Secp256k1, result.to_bytes_be().to_vec()))
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
            k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::Secp256k1,
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
            k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::Secp256k1,
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
        let scalar = K256Scalar::from_bytes_be(&s.value.into())
            .map_err(|_| Error::CurveError("Invalid scalar".to_string()))?;
        
        let result = (point * scalar).to_affine();
        let encoded = result.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Ok(Point::new(
                    CurveType::Secp256k1,
                    x.to_vec(),
                    y.to_vec(),
                ))
            }
            _ => Err(Error::CurveError("Expected uncompressed coordinates".to_string())),
        }
    }
}

impl Curve for Secp256k1 {
    fn curve_type(&self) -> CurveType {
        CurveType::Secp256k1
    }
    
    fn random_scalar(&self) -> Result<Scalar> {
        let mut rng = rand::thread_rng();
        let scalar = K256Scalar::random(&mut rng);
        Ok(Scalar::new(CurveType::Secp256k1, scalar.to_bytes_be().to_vec()))
    }
    
    fn scalar_from_bytes(&self, bytes: &[u8]) -> Result<Scalar> {
        let scalar = K256Scalar::from_bytes_be(bytes.into())
            .map_err(|_| Error::CurveError("Invalid scalar bytes".to_string()))?;
        Ok(Scalar::new(CurveType::Secp256k1, scalar.to_bytes_be().to_vec()))
    }
    
    fn scalar_from_u64(&self, value: u64) -> Result<Scalar> {
        let scalar = K256Scalar::from(value);
        Ok(Scalar::new(CurveType::Secp256k1, scalar.to_bytes_be().to_vec()))
    }
    
    fn generator(&self) -> Point {
        let generator = ProjectivePoint::generator().to_affine();
        let encoded = generator.to_encoded_point(false);
        let coords = encoded.coordinates();
        
        match coords {
            k256::elliptic_curve::sec1::Coordinates::Uncompressed { x, y } => {
                Point::new(CurveType::Secp256k1, x.to_vec(), y.to_vec())
            }
            _ => unreachable!("Generator should have uncompressed coordinates"),
        }
    }
    
    fn point_from_bytes(&self, bytes: &[u8]) -> Result<Point> {
        Self::point_from_compressed(bytes)
    }
    
    fn order(&self) -> Scalar {
        // secp256k1 order
        let order_bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
            0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
            0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
        ];
        Scalar::new(CurveType::Secp256k1, order_bytes.to_vec())
    }
    
    fn field_modulus(&self) -> Scalar {
        // secp256k1 field modulus
        let modulus_bytes = [
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xfe, 0xff, 0xff, 0xfc, 0x2f
        ];
        Scalar::new(CurveType::Secp256k1, modulus_bytes.to_vec())
    }
} 