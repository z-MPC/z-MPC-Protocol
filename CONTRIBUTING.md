# Contributing to z-MPC

Thank you for your interest in contributing to z-MPC! This document provides guidelines for contributing to this project.

## 🚀 Quick Start

### Prerequisites
- Rust 1.70+ 
- Git
- Basic knowledge of cryptography and distributed systems

### Setup Development Environment

1. **Fork the repository**
   ```bash
   git clone https://github.com/your-username/z-mpc.git
   cd z-mpc
   ```

2. **Install dependencies**
   ```bash
   cargo build
   ```

3. **Run tests**
   ```bash
   cargo test
   cargo test --test integration_test
   ```

## 📋 Contribution Guidelines

### Code Style
- Follow Rust coding conventions
- Use `cargo fmt` for formatting
- Use `cargo clippy` for linting
- Write comprehensive tests for new features

### Commit Messages
Use conventional commit format:
```
type(scope): description

[optional body]

[optional footer]
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

### Pull Request Process

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes**
   - Write code following the style guide
   - Add tests for new functionality
   - Update documentation if needed

3. **Run tests locally**
   ```bash
   cargo test
   cargo clippy
   cargo fmt -- --check
   ```

4. **Submit a pull request**
   - Provide a clear description of changes
   - Reference any related issues
   - Ensure all CI checks pass

## 🧪 Testing

### Running Tests
```bash
# Unit tests
cargo test

# Integration tests
cargo test --test integration_test

# Specific test
cargo test test_name

# With output
cargo test -- --nocapture
```

### Adding Tests
- Add unit tests in the same file as the code
- Add integration tests in `tests/` directory
- Test both success and error cases
- Test edge cases and boundary conditions

## 🔒 Security

### Security Vulnerabilities
If you discover a security vulnerability, please:
1. **DO NOT** create a public issue
2. Email security@z-mpc.dev (if available)
3. Or contact maintainers privately

### Security Best Practices
- Never commit secrets or private keys
- Use secure random number generators
- Validate all inputs
- Follow cryptographic best practices

## 📚 Documentation

### Code Documentation
- Document all public APIs
- Use Rust doc comments (`///`)
- Include examples in documentation
- Keep README.md updated

### API Documentation
```bash
# Generate documentation
cargo doc --no-deps --open
```

## 🏗️ Architecture

### Project Structure
```
src/
├── lib.rs          # Main library entry point
├── error.rs        # Error handling
├── types.rs        # Common types
├── curve/          # Elliptic curve implementations
├── laurent.rs      # Laurent series secret sharing
├── pedersen.rs     # Pedersen commitments
├── zk_proof.rs     # Zero-knowledge proofs
├── network.rs      # Network communication
└── main.rs         # CLI interface
```

### Key Components
- **Laurent Series**: Core secret sharing algorithm
- **Pedersen Commitments**: Commitment scheme
- **Zero-Knowledge Proofs**: Proof of knowledge
- **Network Layer**: Distributed communication

## 🐛 Bug Reports

### Before Reporting
1. Check existing issues
2. Try the latest version
3. Reproduce the issue

### Bug Report Template
```markdown
**Description**
Brief description of the issue

**Steps to Reproduce**
1. Step 1
2. Step 2
3. Step 3

**Expected Behavior**
What should happen

**Actual Behavior**
What actually happens

**Environment**
- OS: [e.g., Ubuntu 20.04]
- Rust version: [e.g., 1.70.0]
- z-MPC version: [e.g., 0.1.0]

**Additional Information**
Any other relevant information
```

## 💡 Feature Requests

### Before Requesting
1. Check if the feature already exists
2. Consider if it fits the project scope
3. Think about implementation complexity

### Feature Request Template
```markdown
**Problem**
Description of the problem this feature would solve

**Proposed Solution**
Description of the proposed solution

**Alternatives Considered**
Other solutions you've considered

**Additional Context**
Any other relevant information
```

## 🏷️ Release Process

### Versioning
We follow [Semantic Versioning](https://semver.org/):
- **MAJOR**: Breaking changes
- **MINOR**: New features (backward compatible)
- **PATCH**: Bug fixes (backward compatible)

### Release Checklist
- [ ] All tests pass
- [ ] Documentation is updated
- [ ] CHANGELOG.md is updated
- [ ] Version is bumped
- [ ] Release notes are written

## 🤝 Community

### Getting Help
- Check the documentation
- Search existing issues
- Ask questions in discussions
- Join our community chat (if available)

### Code of Conduct
- Be respectful and inclusive
- Help others learn
- Give constructive feedback
- Follow the project's code of conduct

## 📄 License

By contributing to z-MPC, you agree that your contributions will be licensed under the MIT License.

---

Thank you for contributing to z-MPC! 🎉 