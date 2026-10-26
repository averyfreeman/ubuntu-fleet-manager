# install.py
"""
Legacy system installer for Ubuntu MCP Server.

New installations should follow README.md and use uv directly.
"""

import os
import sys
import subprocess
import shutil
from pathlib import Path


class UbuntuMCPInstaller:
    """Installer for Ubuntu MCP Server"""

    def __init__(self):
        """Set the system installation, user configuration, and service paths."""
        self.install_dir = Path("/opt/ubuntu-mcp")
        self.config_dir = Path.home() / ".config" / "ubuntu-mcp"
        self.service_file = "/etc/systemd/system/ubuntu-mcp.service"

    def check_prerequisites(self) -> bool:
        """Check if system meets prerequisites"""
        print("Checking prerequisites...")

        # Check Python version
        if sys.version_info < (3, 10):
            print("Error: Python 3.10 or higher required")
            return False

        # Check if running on Ubuntu
        try:
            with open('/etc/os-release', 'r') as f:
                content = f.read()
                if 'ubuntu' not in content.lower():
                    print("Warning: This appears to not be Ubuntu")
        except FileNotFoundError:
            print("Warning: Cannot detect OS version")

        return True

    def install_dependencies(self) -> bool:
        """Install required Python packages"""
        print("Installing dependencies...")

        try:
            uv_executable = shutil.which("uv")
            if not uv_executable:
                print("uv is required; follow README.md to install it")
                return False
            subprocess.run([
                uv_executable, "venv", str(self.install_dir / ".venv"),
                "--managed-python", "-p", "3.12"
            ], check=True)
            subprocess.run([
                uv_executable, "sync", "--directory", str(self.install_dir), "--frozen"
            ], check=True)
            return True
        except subprocess.CalledProcessError as e:
            print(f"Failed to install dependencies: {e}")
            return False

    def create_directories(self) -> bool:
        """Create necessary directories"""
        print("Creating directories...")

        try:
            self.install_dir.mkdir(parents=True, exist_ok=True)
            self.config_dir.mkdir(parents=True, exist_ok=True)

            # Set appropriate permissions
            os.chmod(self.install_dir, 0o755)
            os.chmod(self.config_dir, 0o700)

            return True
        except Exception as e:
            print(f"Failed to create directories: {e}")
            return False

    def install_files(self) -> bool:
        """Install server files"""
        print("Installing server files...")

        try:
            current_dir = Path(__file__).resolve().parent
            for filename in ("pyproject.toml", "uv.lock", "README.md"):
                shutil.copy2(current_dir / filename, self.install_dir / filename)
            shutil.copytree(
                current_dir / "ubuntu_mcp_server",
                self.install_dir / "ubuntu_mcp_server",
                dirs_exist_ok=True,
            )

            return True
        except Exception as e:
            print(f"Failed to install files: {e}")
            return False

    def create_service_file(self) -> bool:
        """Create systemd service file"""
        print("Creating systemd service...")

        service_content = f"""[Unit]
Description=Ubuntu MCP Server
After=network.target

[Service]
Type=simple
User={os.getenv('USER', 'ubuntu')}
Group={os.getenv('USER', 'ubuntu')}
WorkingDirectory={self.install_dir}
ExecStart={self.install_dir}/.venv/bin/ubuntu-mcp-server
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
"""

        try:
            with open(self.service_file, 'w') as f:
                f.write(service_content)

            os.chmod(self.service_file, 0o644)
            return True
        except Exception as e:
            print(f"Failed to create service file: {e}")
            return False

    def install(self) -> bool:
        """Run complete installation"""
        print("Starting Ubuntu MCP Server installation...")

        if not self.check_prerequisites():
            return False

        steps = [
            self.create_directories,
            self.install_files,
            self.install_dependencies,
            self.create_service_file
        ]

        for step in steps:
            if not step():
                print(f"Installation failed at step: {step.__name__}")
                return False

        print("Installation completed successfully!")
        print(f"Config directory: {self.config_dir}")
        print(f"Install directory: {self.install_dir}")
        print("\nTo start the service:")
        print("sudo systemctl enable ubuntu-mcp")
        print("sudo systemctl start ubuntu-mcp")

        return True


def main():
    """Main installation function"""
    if os.geteuid() != 0:
        print("This installer should be run with sudo privileges")
        print("Usage: sudo python3 install.py")
        return 1

    installer = UbuntuMCPInstaller()
    success = installer.install()
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
