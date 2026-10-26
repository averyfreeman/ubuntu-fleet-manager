# Contributing to Ubuntu MCP Server

We're thrilled that you're interested in contributing to the Ubuntu MCP Server! This document provides guidelines and information for contributors.

## 🎯 Project Vision

Our mission is to provide a **security-first**, production-ready MCP server that enables AI assistants to safely interact with Ubuntu systems. Every contribution should align with these core principles:

1. **Security First** - Security is never optional or "nice to have"
2. **Fail Safe** - Default to restrictive permissions and explicit allowlists
3. **Defense in Depth** - Multiple security layers with comprehensive validation
4. **Transparency** - Clear audit trails and understandable error messages
5. **Production Ready** - Code quality suitable for production environments

## 🛠️ Development Setup

### Prerequisites
- Ubuntu 18.04+ (primary development environment)
- Python 3.10+
- Git
- [uv](https://docs.astral.sh/uv/getting-started/installation/)
- Basic knowledge of system security principles

### Setup Steps

1. **Fork and Clone**
   ```bash
   git clone https://github.com/averyfreeman/codex-mcp-for-ubuntu.git
   cd codex-mcp-for-ubuntu
   ```

2. **Environment Setup**
   ```bash
   uv venv .venv --managed-python -p 3.12
   uv sync
   ```

3. **Verify Installation**
   ```bash
   uv run python -m unittest discover -s tests -v
   ```

## 🔄 Development Workflow

### Branch Naming
- `feature/description` - New features
- `fix/description` - Bug fixes
- `security/description` - Security improvements
- `docs/description` - Documentation updates

### Commit Messages
Follow conventional commits format:
```
type(scope): brief description

Detailed description if needed

- Breaking changes noted with BREAKING CHANGE:
- References to issues: Fixes #123
```

Examples:
- `feat(security): add symlink resolution validation`
- `fix(commands): prevent shell injection in apt commands`
- `docs(readme): update installation instructions`

## 🧪 Testing Requirements

All contributions must include appropriate tests and pass existing test suites.

### Required Tests

1. **Functionality Tests**
   ```bash
   uv run python -m unittest discover -s tests -v
   ```

2. **Security Tests**
   ```bash
   uv run python -m unittest discover -s tests -v
   ```

3. **Custom Tests**
   Add tests for new functionality in the appropriate test functions.

### Test Coverage
- New functions must have corresponding tests
- Security-related code requires negative testing (verify attacks are blocked)
- Edge cases and error conditions must be tested

## 🔒 Security Guidelines

### Security Review Process
All security-related changes require:
1. Threat modeling for new features
2. Security test cases demonstrating protection
3. Documentation of security implications
4. Code review by maintainers

### Security Principles

**Path Validation**:
- Always resolve symlinks before path checks
- Use allowlists over denylists when possible
- Validate against canonical paths
- Handle edge cases (empty paths, special characters, etc.)

**Command Execution**:
- Never use shell=True in subprocess calls
- Use shlex.split() for command parsing
- Validate commands against allowlists
- Sanitize all user inputs

**Resource Protection**:
- Implement timeouts for all operations
- Limit file sizes, output sizes, and directory listings
- Prevent resource exhaustion attacks
- Monitor resource usage

### Common Security Pitfalls

❌ **Don't do this**:
```python
# Direct path concatenation
path = base_path + "/" + user_input

# Shell execution with user input
os.system(f"ls {user_path}")

# Trusting user input
if user_path.startswith("/safe/"):
    allow_access()
```

✅ **Do this instead**:
```python
# Safe path joining with validation
path = security_checker.validate_path_access(
    os.path.join(base_path, user_input)
)

# Safe command execution
subprocess.run(["ls", validated_path], ...)

# Canonical path checking
canonical_path = resolve_path_safely(user_path)
if canonical_path.startswith(safe_canonical_path):
    allow_access()
```

## 📝 Code Standards

### Python Style
- Follow PEP 8 style guidelines
- Use type hints for all public functions
- Maximum line length: 100 characters
- Use meaningful variable and function names

### Documentation
- All public functions must have docstrings
- Include parameter types and descriptions
- Document security implications for security-related code
- Add usage examples for complex functions

### Error Handling
- Use specific exception types
- Provide meaningful error messages
- Log security violations appropriately
- Never expose internal paths or system details in error messages

## 🎨 Code Architecture

### Modular Design
The codebase follows a clear separation of concerns:

```
SecurityPolicy     - Configuration and policy definitions
SecurityChecker    - Path validation and command verification
AuditLogger       - Security event logging
SecureUbuntuController - Main business logic with security integration
MCPServer Tools     - MCP protocol interface layer
```

### Adding New Features

1. **Security Policy Updates**
   ```python
   # Add new configuration options to SecurityPolicy
   @dataclass
   class SecurityPolicy:
       # ... existing fields
       new_security_option: bool = False
   ```

2. **Security Validation**
   ```python
   # Add validation logic to SecurityChecker
   def validate_new_operation(self, params: str) -> str:
       # Implement security checks
       pass
   ```

3. **Controller Implementation**
   ```python
   # Add business logic to SecureUbuntuController
   def new_operation(self, params: str) -> Dict[str, Any]:
       validated_params = self.security_checker.validate_new_operation(params)
       # Implementation
       self.audit_logger.log_operation("NEW_OP", params, self.current_user, True)
   ```

4. **MCP Tool Interface**
   ```python
   # Add MCP tool in create_ubuntu_mcp_server
   @mcp.tool("new_operation")
   async def new_operation(params: str) -> str:
       try:
           result = controller.new_operation(params)
           return json.dumps(result, indent=2)
       except Exception as e:
           return format_error(e)
   ```

## 🐛 Issue Reporting

### Bug Reports
Use the bug report template and include:
- Operating system and version
- Python version
- Exact error messages
- Steps to reproduce
- Expected vs actual behavior

### Security Issues
**Do not create public issues for security vulnerabilities!**
- Email avery@unixgreybeard.org
- Include detailed description and proof of concept
- Allow time for investigation before public disclosure

### Feature Requests
- Describe the use case and motivation
- Consider security implications
- Propose implementation approach
- Discuss compatibility with existing security model

## 🔍 Code Review Process

### Review Criteria
- [ ] Functionality works as intended
- [ ] Security principles followed
- [ ] Tests pass and cover new functionality
- [ ] Documentation updated
- [ ] No breaking changes (unless explicitly discussed)
- [ ] Performance implications considered

### Security-Focused Review
- [ ] Input validation implemented
- [ ] Path traversal prevention verified
- [ ] Command injection prevention verified
- [ ] Resource limits respected
- [ ] Audit logging added
- [ ] Error messages don't leak sensitive information

## 📋 Release Process

### Version Numbering
We follow semantic versioning (MAJOR.MINOR.PATCH):
- MAJOR: Breaking changes or major security updates
- MINOR: New features, backward compatible
- PATCH: Bug fixes, security patches

### Release Checklist
- [ ] All tests pass
- [ ] Security review completed
- [ ] Documentation updated
- [ ] CHANGELOG.md updated
- [ ] Version numbers updated
- [ ] Release notes prepared

## 🤝 Community Guidelines

### Code of Conduct
- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn
- Assume positive intent

### Communication
- Use clear, concise language
- Provide context for decisions
- Share knowledge and resources
- Ask questions when unsure

## 🎓 Resources

### Security Learning
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Python Security Best Practices](https://python-security.readthedocs.io/)
- [Secure Coding in Python](https://wiki.python.org/moin/Security)

### Python Development
- [PEP 8 Style Guide](https://pep8.org/)
- [Python Type Hints](https://docs.python.org/3/library/typing.html)
- [Python Testing Best Practices](https://docs.python-guide.org/writing/tests/)

## 📞 Getting Help

- **General Questions**: Create a GitHub discussion
- **Bug Reports**: Create a GitHub issue with the bug template
- **Security Issues**: Email avery@unixgreybeard.org
- **Feature Ideas**: Create a GitHub issue with the feature template

---

Thank you for contributing to the security of AI system interactions! Every contribution, no matter how small, helps make AI systems safer for everyone.
