# Security Policy

## Reporting Security Vulnerabilities

🚨 **Please do not report security vulnerabilities through public GitHub issues.**

If you discover a security vulnerability, please send an email to **radjackbartok@proton.me** with:

- A description of the vulnerability
- Steps to reproduce the issue
- Potential impact assessment
- Any suggested fixes (if available)

We will acknowledge receipt within 48 hours and provide a detailed response within 7 days.

## Security Model

### Core Security Principles

1. **Defense in Depth** - Multiple security layers protect against various attack vectors
2. **Fail Safe** - Default to restrictive permissions with explicit allowlists
3. **Least Privilege** - Minimum necessary permissions for intended functionality
4. **Audit Trail** - Comprehensive logging of all security-relevant operations
5. **Input Validation** - All user inputs validated at multiple levels

### Security Boundaries

#### What We Protect Against

✅ **Path Traversal Attacks**
- Symlink resolution prevents directory traversal
- Canonical path validation against allowlists
- Protection against `../` and absolute path bypasses

✅ **Command Injection**
- Safe argument parsing with `shlex`
- Command whitelist/blacklist validation
- No shell interpretation by default

✅ **Resource Exhaustion**
- File size limits prevent memory exhaustion
- Command timeouts prevent hanging processes
- Output size limits prevent log flooding

✅ **Information Disclosure**
- Error messages don't expose sensitive paths
- File permission validation
- Server self-protection (prevents access to own files)

✅ **Privilege Escalation**
- No sudo by default (explicit configuration required)
- Process group isolation
- Environment variable sanitization

### Security Policies

#### Secure Policy (Default - Recommended for Production)
```python
SecurityPolicy(
    allowed_paths=["~/"],
    forbidden_paths=["/etc", "/root", "/boot", "/sys", "/proc", "/dev", "/usr", "/bin", "/sbin"],
    allowed_commands=["ls", "cat", "echo", "pwd", "whoami", "date", "find", "grep", "apt"],
    forbidden_commands=["rm", "dd", "shutdown", "reboot", "mount", "chmod", "chown", "su", "sudo"],
    max_command_timeout=15,
    max_file_size=1024*1024,  # 1MB
    allow_sudo=False,
    resolve_symlinks=True,
    audit_actions=True
)
```

The server stores audit logs at `~/.local/state/ubuntu-mcp/audit.log` and
creates private temporary fixtures under `~/.local/state/ubuntu-mcp/tmp`.
Shared system temporary directories are not part of the default allowlist.

### Security Best Practices

#### For Administrators

**Installation Security**:
- Use dedicated user account for the MCP server
- Install in isolated directory with appropriate permissions
- Use virtual environment to isolate dependencies
- Regularly update dependencies and monitor for vulnerabilities

**Configuration Security**:
- Start with the most restrictive policy (secure)
- Only add permissions as explicitly needed
- Document all policy changes and justifications
- Regular review of security policies and configurations

#### For Users

**Safe Usage Patterns**:
- Be specific about file paths (avoid wildcards when possible)
- Review AI-suggested commands before execution
- Use development policy only in isolated environments
- Report suspicious behavior or unexpected access patterns

### Security Contact

For security-related questions or concerns:

- **Maintainer**: Avery Freeman
- **Email**: avery@unixgreybeard.org
- **Response Time**: 48 hours for acknowledgment, 7 days for detailed response

---

**Last Updated**: 2026-09-06
**Next Review**: 2027-09-06

*This security policy is a living document and will be updated as the project evolves and new security considerations are identified.*
