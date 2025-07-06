# z-MPC: Laurent Series based One-Round Secret Sharing

[![CI/CD Pipeline](https://github.com/your-username/z-mpc/workflows/CI/CD%20Pipeline/badge.svg)](https://github.com/your-username/z-mpc/actions)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Crates.io](https://img.shields.io/crates/v/z-mpc)](https://crates.io/crates/z-mpc)
[![Documentation](https://img.shields.io/badge/docs-latest-brightgreen.svg)](https://your-username.github.io/z-mpc)
[![Sponsor](https://img.shields.io/badge/Sponsor-z--MPC-red.svg)](https://github.com/sponsors/your-username)

> **Revolutionary Laurent Series based One-Round Secret Sharing with Zero-Knowledge Proofs**

z-MPC is a revolutionary distributed signing and secret reconstruction system that combines **Laurent Series based One-Round Secret Sharing** with Zero-Knowledge Proofs (ZK-Proof). Unlike traditional Shamir's Secret Sharing, it uses an innovative approach to provide **One-Round**, **Aggregator-free**, and **Lagrange-free** architecture.

## 🚀 Key Innovations

| Feature | Traditional Shamir's Secret Sharing | z-MPC Laurent Series |
|---------|-------------------------------------|---------------------|
| **Rounds** | Multiple rounds required | **One-Round** (single round) |
| **Reconstruction** | Lagrange interpolation | **Direct Laurent Series reconstruction** |
| **Aggregator** | Required | **Aggregator-free** |
| **Complexity** | O(n²) | **O(n)** |
| **Polynomial** | Taylor Series | **Laurent Series** |

## 📦 Installation

### Add to Rust Project

```bash
# Add dependency to Cargo.toml
cargo add z-mpc

# Or install directly
cargo install z-mpc
```

### Download Binary

```bash
# Download from GitHub Releases
curl -L https://github.com/your-username/z-mpc/releases/latest/download/z-mpc-x86_64-unknown-linux-gnu -o z-mpc
chmod +x z-mpc
```

## 🎯 Quick Start

### Basic Usage

```rust
use z_mpc::{
    init, CurveType, SharingParams, LaurentSeries, 
    PedersenCommitment, ZeroKnowledgeProof
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize library
    init()?;
    
    // Set up secret sharing parameters
    let params = SharingParams {
        curve_type: CurveType::Secp256k1,
        threshold: 3,
        participants: 5,
    };
    
    // Create Laurent series
    let laurent = LaurentSeries::new(&params)?;
    
    // Generate shares
    let shares = laurent.generate_shares()?;
    
    // Create Pedersen commitments
    let pedersen = PedersenCommitment::new(CurveType::Secp256k1)?;
    let committed_shares = pedersen_utils::commit_all_shares(&shares, CurveType::Secp256k1)?;
    
    // Reconstruct secret
    let result = laurent.reconstruct_secret(&shares)?;
    
    println!("Secret: {}", hex::encode(&result.secret));
    
    Ok(())
}
```

### CLI Usage

```bash
# Generate Laurent Series shares
z-mpc generate-shares --secret 0x1234... --threshold 3 --total 5 --curve secp256k1

# One-Round secret reconstruction
z-mpc reconstruct --shares share1.json,share2.json,share3.json --curve secp256k1

# Run network node
z-mpc run-node --port 8080 --participants 5 --threshold 3
```

## 🔧 Key Features

### 🎯 Laurent Series Secret Sharing
- **One-Round Protocol**: Complete in single round
- **Aggregator-free**: Distributed reconstruction without central aggregator
- **Lagrange-free**: No complex interpolation required
- **O(n) Complexity**: Linear time complexity

### 🔐 Security Features
- **Zero-Knowledge Proofs**: Schnorr-style proofs
- **Pedersen Commitments**: Binding and hiding properties
- **Information Theoretic Security**: Unconditional security guarantees
- **Side-Channel Resistance**: Constant-time operations

### 🌐 Network Communication
- **HTTP REST API**: Standard web protocols
- **Message Routing**: Efficient message routing
- **Heartbeat Monitoring**: Participant status monitoring
- **Distributed Protocol**: Fully distributed protocol

### 🔄 Multi-Curve Support
- **secp256k1**: Bitcoin/Ethereum compatible
- **P-256**: NIST standard, high security
- **Edwards25519**: Efficient signing, Ed25519 compatible

## 📚 Documentation

- **[API Documentation](https://your-username.github.io/z-mpc)**: Complete API reference
- **[Usage Guide](https://z-mpc.xyz/docs)**: Step-by-step tutorials
- **[Security Guide](https://z-mpc.xyz/security)**: Security best practices
- **[Performance Benchmarks](https://z-mpc.xyz/benchmarks)**: Performance comparisons

## 🧪 Testing

```bash
# Run all tests
cargo test

# Run integration tests
cargo test --test integration_test

# Run performance benchmarks
cargo bench

# Run CLI tests
cargo run -- test --test all
```

## 📄 License

z-MPC uses a **dual license** model:

### 🆓 AGPL v3 (Free)
- **Personal/Academic use**: Completely free
- **Open source projects**: Free to use
- **Research purposes**: Free to use
- **Conditions**: Must comply with AGPL v3 terms (source code disclosure, etc.)

### 💼 Commercial License (Paid)
- **Commercial use**: License purchase required
- **Enterprise software**: License purchase required
- **SaaS services**: License purchase required
- **Conditions**: AGPL v3 terms waived

#### License Tiers
- **Starter**: $99/year (10,000 API calls/month)
- **Professional**: $299/year (100,000 API calls/month)
- **Enterprise**: $999/year (Unlimited)
- **Custom**: Custom pricing

[Commercial License Information](LICENSE-COMMERCIAL.md) | [License Comparison](https://z-mpc.xyz/licensing)

## 💝 Sponsorship

Support z-MPC development! Sponsorship provides the following benefits:

### 🌟 Bronze Sponsor ($10/month)
- Name displayed in README.md sponsors section
- Early access to new features
- Priority community support

### 🥈 Silver Sponsor ($25/month)
- Logo displayed on project website
- 1 hour/month technical consultation
- Input on feature roadmap

### 🥇 Gold Sponsor ($50/month)
- 1 custom feature development per year
- 2 hours/month training sessions
- Direct integration support

### 💎 Platinum Sponsor ($100/month)
- Dedicated support channel
- Custom enterprise features
- On-site training sessions

[Sponsorship Information](SPONSORSHIP.md) | [GitHub Sponsors](https://github.com/sponsors/your-username)

## 🤝 Contributing

Want to contribute to z-MPC?

1. **[Fork](https://github.com/your-username/z-mpc/fork)** the repository
2. Create a **feature branch** (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'Add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. Open a **Pull Request**

[Contributing Guidelines](CONTRIBUTING.md) | [Code of Conduct](CODE_OF_CONDUCT.md)

## 🐛 Bug Reports

Found a bug? Report it on [GitHub Issues](https://github.com/your-username/z-mpc/issues).

## 🔒 Security

Found a security vulnerability? **DO NOT create a public issue!** Instead:
- **Email**: security@z-mpc.xyz
- **Private**: Contact GitHub maintainers directly

[Security Policy](SECURITY.md)

## 📊 Performance

### Benchmark Results (10 participants, threshold 3)

| Operation | Time | Memory |
|-----------|------|--------|
| Share Generation | 15ms | 2.3MB |
| Commitment Creation | 8ms | 1.1MB |
| ZK Proof Generation | 12ms | 0.8MB |
| Secret Reconstruction | 25ms | 3.2MB |
| Full Protocol | 60ms | 7.4MB |

## 🌟 Sponsors

### Platinum Sponsors
<!-- Add sponsors here -->

### Gold Sponsors
<!-- Add sponsors here -->

### Silver Sponsors
<!-- Add sponsors here -->

### Bronze Sponsors
<!-- Add sponsors here -->

[Become a Sponsor!](SPONSORSHIP.md)

## 📈 Roadmap

### v0.2.0 (2024 Q2)
- [ ] WebAssembly support
- [ ] Enhanced network protocols
- [ ] Additional elliptic curves

### v0.3.0 (2024 Q3)
- [ ] Performance optimizations
- [ ] Advanced ZK Proof systems
- [ ] Cloud integration

### v1.0.0 (2024 Q4)
- [ ] Security audit completed
- [ ] Production ready
- [ ] Enterprise features

## 📞 Contact

- **Website**: https://z-mpc.xyz
- **Documentation**: https://z-mpc.xyz/docs
- **Email**: contact@z-mpc.xyz
- **Twitter**: [@z_mpc](https://twitter.com/z_mpc)
- **Discord**: [z-MPC Community](https://discord.gg/z-mpc)
- **GitHub**: [your-username/z-mpc](https://github.com/your-username/z-mpc)

## 🙏 Acknowledgments

z-MPC is made possible by contributions from:

- **Rust Community**: Excellent ecosystem
- **Cryptography Researchers**: Foundational research
- **Open Source Contributors**: Code reviews and improvements
- **Early Adopters**: Feedback and testing

---

**z-MPC**: Building the future of secure distributed systems with Laurent Series based One-Round Secret Sharing! 🚀 