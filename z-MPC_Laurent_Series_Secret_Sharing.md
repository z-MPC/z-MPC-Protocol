# z-MPC: Laurent Series 기반 One-Round Secret Sharing

## 프로젝트 개요

z-MPC는 **Laurent Series 기반 One-Round Secret Sharing**과 Zero-Knowledge Proofs(ZK-Proof)를 결합한 분산 서명 및 시크릿 재구성 시스템입니다. 이는 기존의 Shamir's Secret Sharing과는 다른 혁신적인 접근법을 사용합니다.

## 핵심 혁신: Laurent Series Secret Sharing

### 기존 Shamir's Secret Sharing vs Laurent Series Secret Sharing

| 특징 | Shamir's Secret Sharing | Laurent Series Secret Sharing |
|------|------------------------|------------------------------|
| **라운드 수** | 다중 라운드 필요 | **One-Round** (단일 라운드) |
| **재구성 방법** | Lagrange 보간법 | **Laurent Series 직접 재구성** |
| **중앙 집계자** | 필요 (Aggregator) | **Aggregator-free** |
| **계산 복잡도** | O(n²) | **O(n)** |
| **다항식 표현** | Taylor Series | **Laurent Series** |

### Laurent Series의 수학적 기반

Laurent Series는 다음과 같은 형태로 표현됩니다:

```
f(x) = Σ(aₙ * xⁿ) for n ∈ ℤ
```

여기서:
- `aₙ`: Laurent 계수 (Laurent Coefficients)
- `x`: 변수
- `n`: 정수 지수 (음수 포함)

### 시크릿 쉐어링 과정

1. **시크릿 생성**: 원본 시크릿 `s`를 Laurent Series로 변환
2. **계수 분산**: Laurent 계수들을 각 참가자에게 분배
3. **One-Round 재구성**: 참가자들이 각자의 계수를 공유하여 직접 재구성

## 프로젝트 아키텍처

### 모듈 구조

```
src/
├── lib.rs              # 메인 라이브러리 모듈
├── error.rs            # 에러 처리
├── types.rs            # 공통 타입 정의
├── curve/              # 곡선 모듈
│   ├── mod.rs          # 공통 Curve trait
│   ├── secp256k1.rs    # secp256k1 구현
│   ├── p256.rs         # P-256 구현
│   └── ed25519.rs      # Edwards25519 구현
├── laurent.rs          # Laurent Series 시크릿 쉐어링
├── pedersen.rs         # Pedersen Commitment
├── zk_proof.rs         # Zero-Knowledge Proof
├── network.rs          # 네트워크 통신
└── main.rs             # CLI 인터페이스
```

### 핵심 타입 정의

```rust
// Laurent Series 계수
pub struct LaurentCoefficients {
    pub coefficients: Vec<Scalar>,
    pub degree: usize,
}

// 시크릿 쉐어링 파라미터
pub struct SharingParams {
    pub threshold: usize,      // 임계값
    pub total_shares: usize,   // 총 쉐어 수
    pub curve_type: CurveType, // 곡선 타입
}

// 쉐어 구조
pub struct Share {
    pub id: u32,
    pub value: Scalar,
    pub commitment: Point,
    pub proof: ZKProof,
}
```

## Laurent Series 구현 세부사항

### 1. 시크릿 생성 및 분산

```rust
// Laurent Series로 시크릿을 쉐어로 변환
pub fn generate_shares(
    secret: &Scalar,
    params: &SharingParams,
) -> Result<Vec<Share>, Error> {
    // 1. 시크릿을 Laurent Series로 변환
    let coefficients = secret_to_laurent_coefficients(secret, params.threshold);
    
    // 2. 각 참가자에게 계수 분배
    let shares = coefficients_to_shares(&coefficients, params);
    
    // 3. Pedersen Commitment 생성
    let shares_with_commitments = add_commitments(shares);
    
    // 4. ZK Proof 생성
    let shares_with_proofs = add_zk_proofs(shares_with_commitments);
    
    Ok(shares_with_proofs)
}
```

### 2. One-Round 재구성

```rust
// Laurent Series를 사용한 직접 재구성
pub fn reconstruct_secret(
    shares: &[Share],
    params: &SharingParams,
) -> Result<ReconstructionResult, Error> {
    // 1. Laurent 계수들 수집
    let coefficients = shares_to_coefficients(shares);
    
    // 2. Laurent Series 직접 재구성 (Lagrange 보간법 없음)
    let secret = laurent_coefficients_to_secret(&coefficients);
    
    // 3. ZK Proof 검증
    verify_all_proofs(shares)?;
    
    Ok(ReconstructionResult {
        secret,
        reconstructed_at: SystemTime::now(),
        participants: shares.len(),
    })
}
```

### 3. Laurent Series 수학 연산

```rust
// 스칼라 거듭제곱 계산 (Laurent Series용)
pub fn scalar_power(base: &Scalar, exponent: i32) -> Scalar {
    if exponent >= 0 {
        base.pow(&[exponent as u64])
    } else {
        // 음수 지수 처리
        let positive_power = base.pow(&[(-exponent) as u64]);
        positive_power.invert()
    }
}

// Laurent Series 평가
pub fn evaluate_laurent_series(
    coefficients: &[Scalar],
    point: &Scalar,
) -> Scalar {
    let mut result = Scalar::zero();
    let mut power = Scalar::one();
    
    for (i, coeff) in coefficients.iter().enumerate() {
        let exponent = i as i32 - (coefficients.len() as i32 / 2);
        let term = coeff * &scalar_power(point, exponent);
        result = result + term;
    }
    
    result
}
```

## 보안 기능

### 1. Pedersen Commitment

```rust
// 쉐어에 대한 Pedersen Commitment 생성
pub fn create_commitment(
    share: &Scalar,
    blinding: &Scalar,
    generator: &Point,
) -> Point {
    generator * share + &Point::generator() * blinding
}

// 배치 검증
pub fn verify_batch_commitments(
    commitments: &[Point],
    shares: &[Scalar],
    blindings: &[Scalar],
) -> bool {
    // 효율적인 배치 검증
    let left_side = commitments.iter().sum::<Point>();
    let right_side = Point::generator() * shares.iter().sum::<Scalar>() 
                   + &Point::generator() * blindings.iter().sum::<Scalar>();
    left_side == right_side
}
```

### 2. Zero-Knowledge Proof

```rust
// Schnorr-style ZK Proof 생성
pub fn generate_zk_proof(
    share: &Scalar,
    commitment: &Point,
    challenge: &Scalar,
) -> ZKProof {
    let random_scalar = Scalar::random();
    let commitment_proof = Point::generator() * random_scalar;
    
    let response = random_scalar + challenge * share;
    
    ZKProof {
        commitment: commitment_proof,
        response,
    }
}

// Fiat-Shamir 휴리스틱을 사용한 검증
pub fn verify_zk_proof(
    proof: &ZKProof,
    commitment: &Point,
    challenge: &Scalar,
) -> bool {
    let expected = Point::generator() * &proof.response;
    let actual = proof.commitment + commitment * challenge;
    expected == actual
}
```

## 네트워크 통신

### 분산 프로토콜

```rust
// 네트워크 메시지 타입
pub enum NetworkMessage {
    ShareDistribution(Share),
    CommitmentExchange(Point),
    ProofVerification(ZKProof),
    SecretReconstruction(Vec<Share>),
    Heartbeat(NodeInfo),
}

// HTTP API 엔드포인트
#[derive(Router)]
pub struct ApiRouter {
    #[post("/distribute")]
    async fn distribute_shares(Json(request): Json<DistributeRequest>) -> Json<DistributeResponse>,
    
    #[post("/commit")]
    async fn exchange_commitments(Json(request): Json<CommitRequest>) -> Json<CommitResponse>,
    
    #[post("/verify")]
    async fn verify_proofs(Json(request): Json<VerifyRequest>) -> Json<VerifyResponse>,
    
    #[post("/reconstruct")]
    async fn reconstruct_secret(Json(request): Json<ReconstructRequest>) -> Json<ReconstructResponse>,
}
```

## 다중 곡선 지원

### 지원 곡선

1. **secp256k1**: Bitcoin/Ethereum 호환
2. **P-256**: NIST 표준, 높은 보안
3. **Edwards25519**: 효율적인 서명, Ed25519 호환

### 곡선 추상화

```rust
pub trait Curve: Send + Sync {
    type Scalar: ScalarOps;
    type Point: PointOps<Scalar = Self::Scalar>;
    
    fn generator() -> Self::Point;
    fn scalar_random() -> Self::Scalar;
    fn point_random() -> Self::Point;
}
```

## CLI 사용법

### 설치 및 빌드

```bash
# Rust 설치
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 프로젝트 빌드
cargo build --release

# CLI 실행
./target/release/z-mpc --help
```

### 주요 명령어

```bash
# Laurent Series 쉐어 생성
z-mpc generate-shares --secret 0x1234... --threshold 3 --total 5 --curve secp256k1

# Pedersen Commitment 생성
z-mpc create-commitment --share-id 1 --value 0xabcd... --curve p256

# ZK Proof 생성
z-mpc generate-proof --share-id 1 --commitment 0xdef0... --curve ed25519

# One-Round 시크릿 재구성
z-mpc reconstruct --shares share1.json,share2.json,share3.json --curve secp256k1

# 네트워크 노드 실행
z-mpc run-node --port 8080 --participants 5 --threshold 3
```

## 성능 및 보안 특징

### 성능 최적화

- **One-Round**: 단일 라운드로 완료
- **Lagrange-free**: 복잡한 보간법 제거
- **배치 연산**: Pedersen Commitment 배치 검증
- **병렬 처리**: 다중 곡선 동시 지원

### 보안 보장

- **정보 이론적 보안**: 임계값 미만의 쉐어로는 시크릿 복구 불가
- **Zero-Knowledge**: 쉐어 값 노출 없이 유효성 증명
- **Pedersen Commitment**: 바인딩 및 은닉성 보장
- **Fiat-Shamir**: 비대화형 ZK Proof

## 테스트 및 검증

### 통합 테스트

```rust
#[tokio::test]
async fn test_full_z_mpc_flow() {
    // 1. 시크릿 생성
    let secret = Scalar::random();
    let params = SharingParams::new(3, 5, CurveType::Secp256k1);
    
    // 2. Laurent Series 쉐어 생성
    let shares = generate_shares(&secret, &params).unwrap();
    
    // 3. 네트워크 분산
    let distributed_shares = distribute_shares(shares).await.unwrap();
    
    // 4. One-Round 재구성
    let reconstructed = reconstruct_secret(&distributed_shares, &params).unwrap();
    
    // 5. 검증
    assert_eq!(reconstructed.secret, secret);
}
```

### 보안 테스트

```rust
#[test]
fn test_threshold_security() {
    // 임계값 미만의 쉐어로는 재구성 불가
    let secret = Scalar::random();
    let params = SharingParams::new(3, 5, CurveType::Secp256k1);
    let shares = generate_shares(&secret, &params).unwrap();
    
    // 2개 쉐어만 사용 (임계값 3 미만)
    let insufficient_shares = &shares[0..2];
    let result = reconstruct_secret(insufficient_shares, &params);
    
    assert!(result.is_err());
}
```

## 결론

z-MPC는 **Laurent Series 기반 One-Round Secret Sharing**이라는 혁신적인 접근법을 통해 기존 Shamir's Secret Sharing의 한계를 극복했습니다:

1. **효율성**: One-Round, Lagrange-free 구조로 계산 복잡도 감소
2. **분산성**: Aggregator-free 구조로 중앙 집중화 제거
3. **보안성**: ZK Proof와 Pedersen Commitment로 강화된 보안
4. **호환성**: 다중 곡선 지원으로 다양한 블록체인 생태계 통합

이 프로젝트는 분산 시스템, 블록체인, 멀티파티 컴퓨테이션 분야에서 새로운 표준이 될 잠재력을 가지고 있습니다. 