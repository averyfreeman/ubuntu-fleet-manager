# Changelog

All notable changes to the Ubuntu MCP Server will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed
- Moved audit logs from shared `/tmp` to the private per-user state directory
  at `~/.local/state/ubuntu-mcp/audit.log`.
- Removed shared system temporary directories from the default security policy.

### Security
- Added symlink-resistant, owner-only audit-log creation.
- Replaced fixed-name temporary security fixtures with private `tempfile` directories.

### Added
- Initial public release preparation
- Comprehensive documentation and contributing guidelines

## [0.2.3] - 2026-09-06

### Changed
- Replaced the legacy MCP server implementation with the updated `MCPServer` implementation.
- Added Codex setup and compatibility alongside other stdio MCP clients.
- Modernized packaging, dependency management, and development workflows around uv.

## [1.0.0] - 2025-06-20

### Added
- **Core Security Framework**
  - Path traversal protection with symlink resolution
  - Command injection prevention with safe argument parsing
  - Resource exhaustion protection (timeouts, file sizes, output limits)
  - Comprehensive audit logging with user attribution
  - Configurable security policies (secure vs development)

- **File Operations**
  - `list_directory()` - Directory listing with metadata and permission checks
  - `read_file()` - File reading with size validation and encoding handling
  - `write_file()` - Atomic file writing with backup creation and directory creation

- **System Operations**
  - `execute_command()` - Safe command execution with whitelist/blacklist filtering
  - `get_system_info()` - System information gathering (OS, memory, disk usage)

- **Package Management**
  - `search_packages()` - APT package search functionality
  - `install_package()` - Package availability checking (listing only for security)

- **Security Features**
  - Symlink resolution to prevent path traversal attacks
  - Command whitelist/blacklist with shlex-based safe parsing
  - Path allowlist/denylist with canonical path validation
  - Process group isolation and timeout enforcement
  - File permission validation
  - Server self-protection (prevents access to own executable files)

- **Testing & Validation**
  - Comprehensive functionality test suite
  - Security validation tests for common attack vectors
  - MCP protocol compliance testing
  - Automated security boundary testing

- **Configuration & Policies**
  - Secure policy (restrictive, production-ready)
  - Development policy (more permissive for development environments)
  - Custom policy creation framework
  - Environment variable configuration support

- **Logging & Monitoring**
  - Structured audit logging to the per-user state directory
  - Security violation logging with context
  - Command execution logging with user attribution
  - File operation logging with success/failure tracking

### Security
- **Defense in Depth Architecture**
  - Multiple validation layers for all operations
  - Fail-safe defaults (deny by default, explicit allow)
  - Input sanitization at multiple levels
  - Output size limiting to prevent information disclosure

- **Attack Prevention**
  - Path traversal protection (e.g., `../../../etc/passwd`)
  - Command injection prevention (e.g., `; rm -rf /`)
  - Symlink attack mitigation
  - Resource exhaustion prevention
  - Information disclosure prevention

- **Audit & Compliance**
  - Complete audit trail for all operations
  - User attribution for all actions
  - Security violation logging
  - Configurable logging levels and destinations

### Performance
- **Optimizations**
  - Direct subprocess execution (no shell interpretation)
  - Atomic file operations to prevent corruption
  - Efficient path resolution with optional caching
  - Process group management for clean termination

### Documentation
- Comprehensive README with security focus
- Installation and configuration guides
- Security policy documentation
- Troubleshooting guide
- Integration examples for Claude Desktop
- API documentation for all MCP tools

### Dependencies
- `mcp>=1.9.0` - Model Context Protocol implementation
- `psutil>=5.9.0` - System information gathering
- Python 3.9+ - Modern Python features and security improvements

---

## Security Notes

### v1.0.0 Security Highlights
This initial release focuses heavily on security, implementing multiple layers of protection:

1. **Path Security**: All file operations use canonical path resolution to prevent directory traversal attacks
2. **Command Security**: Commands are parsed safely and validated against configurable allowlists/denylists
3. **Resource Security**: All operations have timeouts and size limits to prevent resource exhaustion
4. **Audit Security**: Comprehensive logging provides full audit trails for security monitoring
5. **Isolation Security**: Process groups and environment sanitization prevent privilege escalation

### Known Security Considerations
- Symlink resolution is performed on every operation for maximum security (slight performance impact)
- Command whitelist mode is enabled by default in secure policy (may require policy adjustment for specific use cases)
- Audit logs are written to the owner-only per-user state directory by default
- No network operations are currently supported (by design, but may limit some use cases)

### Future Security Enhancements
- Enhanced logging with structured JSON format
- Network operation support with appropriate restrictions
- Container-aware security policies
- Role-based access controls for multi-user environments

---

## Migration Guide

### From Development to Production
When moving from development to production:

1. **Change Security Policy**: Switch from `dev` to `secure` policy
2. **Review Allowed Paths**: Ensure only necessary paths are in the allowlist
3. **Audit Configuration**: Enable audit logging and configure appropriate log retention
4. **Monitor Logs**: Set up monitoring for security violations and unusual activity
5. **Update Dependencies**: Ensure all dependencies are up to date

### Configuration Changes
The server supports multiple configuration methods:
- Command line arguments (`--policy secure`)
- Environment variables (`MCP_POLICY=secure`)
- Configuration files (`config.json`)

---

## Credits

### Contributors
- Initial development and security architecture
- Comprehensive test suite implementation
- Documentation and user experience improvements

### Security Research
Thanks to the security community for best practices and vulnerability research that informed this implementation.

### Acknowledgments
- Model Context Protocol team for the excellent protocol design
- Python security community for ongoing guidance and best practices
- Ubuntu community for providing a secure and stable platform

---

For more information about security features and implementation details, see the [README.md](README.md) and [CONTRIBUTING.md](CONTRIBUTING.md) files.
