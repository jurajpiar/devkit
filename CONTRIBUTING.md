# Contributing to Devkit

Thank you for your interest in contributing to Devkit! This document provides guidelines and information for contributors.

## Code of Conduct

- Be respectful and inclusive
- Focus on constructive feedback
- Assume good intentions

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR_USERNAME/devkit.git`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `make test`
6. Commit and push
7. Open a Pull Request

## Development Setup

```bash
# Install dependencies
go mod download

# Build
go build -o devkit ./cmd/devkit

# Run tests
make test-unit      # Unit tests only
make test-e2e       # End-to-end tests (requires Podman)
make test           # All tests
```

## Security Guidelines

Since Devkit is a security-focused tool, please pay special attention to:

### Do

- Follow the principle of least privilege
- Default to the most secure option
- Make dangerous options explicit and require opt-in
- Add warnings for security-sensitive configurations
- Document security implications of features
- Write tests for security-critical code paths

### Don't

- Add features that require root/sudo by default
- Expose host filesystem without explicit user consent
- Store secrets in code, logs, or config files
- Disable security features without clear warnings
- Add network access where it's not needed

### Reporting Security Issues

If you discover a security vulnerability, please **do not** open a public issue. Instead:

1. Email the maintainers directly (see repository for contact)
2. Include a detailed description of the vulnerability
3. Provide steps to reproduce if possible
4. Allow reasonable time for a fix before public disclosure

## Pull Request Guidelines

### Before Submitting

- [ ] Code compiles without errors: `go build ./...`
- [ ] Tests pass: `make test`
- [ ] No linting errors: `go vet ./...`
- [ ] Code is formatted: `go fmt ./...`
- [ ] Documentation is updated if needed

### PR Description

Please include:

1. **What**: Brief description of changes
2. **Why**: Motivation or issue being fixed
3. **How**: High-level approach (if not obvious)
4. **Testing**: How you tested the changes
5. **Security**: Any security considerations

### Commit Messages

- Use clear, descriptive commit messages
- Start with a verb (Add, Fix, Update, Remove, etc.)
- Reference issues when applicable: `Fix #123`

Good examples:
```
Add total isolation mode with dedicated Podman machine
Fix SSH key setup failing on Alpine containers
Update README with port forwarding documentation
```

## Code Style

- Follow standard Go conventions
- Use `go fmt` for formatting
- Keep functions focused and reasonably sized
- Add comments for non-obvious logic
- Prefer explicit over implicit

## Testing

### Unit Tests

- Test individual functions and components
- Mock external dependencies
- Aim for good coverage of edge cases

### End-to-End Tests

- Test full workflows
- Require a running Podman machine
- Clean up resources after tests

### Security Tests

- Test that security features actually work
- Verify isolation boundaries
- Test attack scenarios the tool should prevent

## Areas for Contribution

### High Priority

- Bug fixes
- Security improvements
- Documentation improvements
- Test coverage

### Feature Ideas

- Support for additional languages (Python, Rust, Go, etc.)
- GUI interface
- Better error messages
- Performance improvements

### Documentation

- Usage examples
- Troubleshooting guides
- Architecture documentation
- Video tutorials

## Questions?

- Open a GitHub Discussion for general questions
- Open an Issue for bugs or feature requests
- Check existing issues before creating new ones

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.

---

Thank you for contributing to Devkit!
