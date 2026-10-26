#!/usr/bin/env python3
"""
Legacy setup helper for Ubuntu MCP Server.

New installations should follow README.md and use uv directly.
"""

import os
import sys
import subprocess
import json
import argparse
import shutil
from pathlib import Path
from typing import Dict, Any


def check_python_version():
    """Ensure Python 3.10+ is being used"""
    if sys.version_info < (3, 10):
        print("❌ Python 3.10 or higher is required!")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    print(f"✅ Python version: {sys.version}")


def check_ubuntu_version():
    """Check if running on supported Ubuntu version"""
    try:
        with open('/etc/os-release', 'r') as f:
            os_info = dict(line.strip().split('=', 1) for line in f if '=' in line)
            name = os_info.get('NAME', '').strip('"')
            version = os_info.get('VERSION_ID', '').strip('"')

            if 'ubuntu' not in name.lower():
                print(f"⚠️  Warning: This server is designed for Ubuntu. Detected: {name}")
                return False

            version_num = float(version)
            if version_num < 18.04:
                print(f"⚠️  Warning: Ubuntu 18.04+ recommended. Detected: {version}")
                return False

            print(f"✅ Ubuntu version: {name} {version}")
            return True
    except Exception as e:
        print(f"⚠️  Could not detect OS version: {e}")
        return False


def create_virtual_environment():
    """Create and setup virtual environment"""
    venv_path = Path('.venv')

    if venv_path.exists():
        print("✅ Virtual environment already exists")
        return

    print("📦 Creating virtual environment...")
    try:
        uv_executable = shutil.which('uv')
        if not uv_executable:
            print("❌ uv is required; follow README.md to install it")
            sys.exit(1)
        subprocess.run([uv_executable, 'venv', '.venv', '--managed-python', '-p', '3.12'], check=True)
        print("✅ Virtual environment created")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        sys.exit(1)


def install_dependencies():
    """Install required dependencies"""
    print("📦 Installing dependencies...")

    uv_executable = shutil.which('uv')
    if not uv_executable:
        print("❌ uv is required; follow README.md to install it")
        sys.exit(1)

    try:
        subprocess.run([uv_executable, 'sync'], check=True)
        print("✅ Dependencies installed successfully")
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        sys.exit(1)


def run_tests():
    """Run functionality and security tests"""
    print("🧪 Running tests...")

    uv_executable = shutil.which('uv')
    if not uv_executable:
        print("❌ uv is required; follow README.md to install it")
        return False

    try:
        result = subprocess.run([uv_executable, 'run', 'python', '-m', 'unittest',
                                 'discover', '-s', 'tests', '-v'],
                              capture_output=True, text=True)
        if result.returncode != 0:
            print(f"❌ Tests failed: {result.stderr}")
            return False

        print("✅ Tests passed!")
        return True
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return False


def generate_claude_config(install_path: str) -> Dict[str, Any]:
    """Generate Claude Desktop configuration"""
    venv_python = f"{install_path}/.venv/bin/python3"
    main_script = f"{install_path}/main.py"

    config = {
        "mcpServers": {
            "secure-ubuntu": {
                "command": venv_python,
                "args": [main_script, "--policy", "secure"],
                "env": {
                    "MCP_LOG_LEVEL": "INFO"
                }
            }
        }
    }
    return config


def setup_claude_integration(install_path: str):
    """Setup Claude Desktop integration"""
    print("🔧 Setting up Claude Desktop integration...")

    # Generate configuration
    config = generate_claude_config(install_path)

    # Default Claude Desktop config path
    claude_config_dir = Path.home() / '.config' / 'claude-desktop'
    claude_config_file = claude_config_dir / 'claude_desktop_config.json'

    print(f"\n📋 Claude Desktop Configuration:")
    print(f"Add this to your Claude Desktop config file:")
    print(f"Config file location: {claude_config_file}")
    print(f"\n{json.dumps(config, indent=2)}")

    # Offer to create the config
    if input("\n❓ Would you like to create/update the Claude Desktop config? (y/N): ").lower() == 'y':
        try:
            claude_config_dir.mkdir(parents=True, exist_ok=True)

            # Merge with existing config if it exists
            existing_config = {}
            if claude_config_file.exists():
                with open(claude_config_file, 'r') as f:
                    existing_config = json.load(f)

            # Merge configurations
            if 'mcpServers' not in existing_config:
                existing_config['mcpServers'] = {}
            existing_config['mcpServers'].update(config['mcpServers'])

            # Write updated config
            with open(claude_config_file, 'w') as f:
                json.dump(existing_config, f, indent=2)

            print(f"✅ Claude Desktop config updated at {claude_config_file}")
            print("⚠️  Please restart Claude Desktop to apply changes")
        except Exception as e:
            print(f"❌ Failed to update Claude Desktop config: {e}")
            print("Please manually add the configuration shown above")


def create_example_config():
    """Create example configuration file"""
    example_config = {
        "server": {
            "name": "secure-ubuntu-controller",
            "version": "0.2.3",
            "description": "Secure Ubuntu MCP Server",
            "log_level": "INFO"
        },
        "security": {
            "policy_name": "secure",
            "allowed_paths": ["~/"],
            "forbidden_paths": ["/etc", "/root", "/boot", "/sys", "/proc"],
            "max_command_timeout": 30,
            "allow_sudo": False,
            "audit_actions": True
        }
    }

    config_file = Path('config.example.json')
    with open(config_file, 'w') as f:
        json.dump(example_config, f, indent=2)

    print(f"✅ Example configuration created at {config_file}")


def print_next_steps(install_path: str):
    """Print next steps for the user"""

    print(f"""
🎉 Installation Complete!

📁 Installation directory: {install_path}

🚀 Next Steps:

1. **Test the server**:
   uv --directory {install_path} run python -m unittest discover -s tests -v

2. **Start the server**:
   uv --directory {install_path} run --frozen ubuntu-mcp-server

3. **Connect Codex**:
   codex mcp add ubuntu -- uv --directory {install_path} run --frozen ubuntu-mcp-server

4. **Claude Desktop Integration** (legacy):
   - Add the configuration shown above to your Claude Desktop config
   - Restart Claude Desktop
   - Test with: "Check my system status"

5. **Customize Security**:
   - Review config.example.json for custom settings
   - Copy to config.json and modify as needed
   - Use --policy dev for development environments

📚 Documentation:
   - README.md - Full documentation
   - CONTRIBUTING.md - Development guide
   - CHANGELOG.md - Version history

🔒 Security:
   - Review allowed_paths and forbidden_paths in your policy
   - Monitor audit logs at ~/.local/state/ubuntu-mcp/audit.log
   - Start with secure policy and adjust as needed

❓ Having issues? Check the troubleshooting section in README.md
""")


def main():
    """Run the legacy setup workflow and return a process-style exit code."""
    parser = argparse.ArgumentParser(description="Setup Secure Ubuntu MCP Server")
    parser.add_argument('--skip-tests', action='store_true', help='Skip running tests')
    parser.add_argument('--skip-claude', action='store_true', help='Skip Claude Desktop setup')
    parser.add_argument('--quiet', action='store_true', help='Minimal output')

    args = parser.parse_args()

    if not args.quiet:
        print("🔒 Secure Ubuntu MCP Server Setup")
        print("==================================")

    install_path = str(Path.cwd().absolute())

    # Check prerequisites
    check_python_version()
    check_ubuntu_version()

    # Setup environment
    create_virtual_environment()
    install_dependencies()

    # Create example configuration
    create_example_config()

    # Run tests unless skipped
    if not args.skip_tests:
        if not run_tests():
            print("⚠️  Tests failed - installation may have issues")
            if input("Continue anyway? (y/N): ").lower() != 'y':
                sys.exit(1)

    # Setup Claude integration unless skipped
    if not args.skip_claude:
        setup_claude_integration(install_path)

    # Show next steps
    if not args.quiet:
        print_next_steps(install_path)

    print("✅ Setup complete!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n❌ Setup interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Setup failed: {e}")
        sys.exit(1)
