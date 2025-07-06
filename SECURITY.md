# Security Policy

## Supported Versions

Use this section to tell people about which versions of your project are currently being supported with security updates.

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1   | :x:                |

## Reporting a Vulnerability

We take security vulnerabilities seriously. If you discover a security vulnerability in z-MPC, please follow these steps:

### 1. **DO NOT** Create a Public Issue

Security vulnerabilities should **never** be reported through public GitHub issues, as this could expose users to potential attacks.

### 2. Contact Security Team

Please report security vulnerabilities by emailing our security team at:
- **Primary**: security@z-mpc.dev (if available)
- **Alternative**: Contact the maintainers directly through GitHub

### 3. Include Required Information

When reporting a vulnerability, please include:

- **Description**: Clear description of the vulnerability
- **Impact**: Potential impact on users and systems
- **Steps to Reproduce**: Detailed steps to reproduce the issue
- **Proof of Concept**: If possible, include a proof of concept
- **Affected Versions**: Which versions are affected
- **Suggested Fix**: If you have suggestions for fixing the issue

### 4. Response Timeline

- **Initial Response**: Within 48 hours
- **Assessment**: Within 1 week
- **Fix Development**: Timeline depends on severity
- **Public Disclosure**: After fix is available

## Security Best Practices

### For Users

1. **Keep Updated**: Always use the latest stable version
2. **Verify Downloads**: Verify checksums of downloaded binaries
3. **Secure Environment**: Run in secure, isolated environments
4. **Key Management**: Use secure key management practices
5. **Network Security**: Use secure network connections

### For Developers

1. **Dependencies**: Regularly update dependencies
2. **Code Review**: All code changes require security review
3. **Testing**: Run security tests before releases
4. **Documentation**: Document security considerations
5. **Monitoring**: Monitor for security issues

## Security Features

### Cryptographic Security

- **Information Theoretic Security**: Unconditional security guarantees
- **Side-Channel Resistance**: Constant-time operations where possible
- **Random Number Generation**: Cryptographically secure RNG
- **Key Derivation**: Secure key derivation functions

### Network Security

- **Transport Security**: HTTPS/TLS for all communications
- **Message Authentication**: Cryptographic message authentication
- **Input Validation**: Comprehensive input sanitization
- **Rate Limiting**: Protection against abuse

### Code Security

- **Memory Safety**: Rust's memory safety guarantees
- **Bounds Checking**: Automatic bounds checking
- **Type Safety**: Strong type system prevents many errors
- **Error Handling**: Secure error reporting

## Security Audit

### Regular Audits

- **Annual Security Review**: Comprehensive security assessment
- **Dependency Audits**: Regular dependency vulnerability scans
- **Code Reviews**: Security-focused code reviews
- **Penetration Testing**: Periodic penetration testing

### Audit Reports

Security audit reports are published when available and appropriate.

## Responsible Disclosure

We follow responsible disclosure practices:

1. **Private Reporting**: Vulnerabilities reported privately
2. **Timely Fixes**: Fixes developed and tested promptly
3. **Coordinated Disclosure**: Public disclosure coordinated with fix release
4. **Credit Given**: Proper credit given to security researchers

## Security Contacts

### Primary Security Contact
- **Email**: security@z-mpc.dev (if available)
- **Response Time**: 48 hours

### Maintainers
- **GitHub**: Contact through GitHub issues (for non-security matters)
- **Discussions**: GitHub Discussions for general questions

## Security Acknowledgments

We thank security researchers who responsibly disclose vulnerabilities to us.

## Security Policy Updates

This security policy may be updated as needed. Significant changes will be announced through:

- GitHub releases
- Project documentation
- Community announcements

---

**Note**: This security policy is designed to protect users and maintain the integrity of the z-MPC project. We appreciate your cooperation in following these guidelines. 