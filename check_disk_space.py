#!/usr/bin/env python3
"""
Demonstrate disk space checking functionality
"""

from main import create_safe_policy, UbuntuController
import json

def check_disk_space():
    """Check disk space using the MCP server functionality"""
    print("💾 Checking Disk Space...")
    print("=" * 40)

    # Create controller
    policy = create_safe_policy()
    controller = UbuntuController(policy)

    # Get system info (includes disk usage)
    info = controller.get_system_info()
    disk = info['disk_usage']

    # Convert to GB
    total_gb = disk['total'] / (1024**3)
    used_gb = disk['used'] / (1024**3)
    free_gb = disk['free'] / (1024**3)
    used_percent = (disk['used'] / disk['total']) * 100

    # Display results
    print(f"📊 Total Disk Space: {total_gb:.1f} GB")
    print(f"🔴 Used Space:       {used_gb:.1f} GB ({used_percent:.1f}%)")
    print(f"🟢 Free Space:       {free_gb:.1f} GB")

    # Visual usage bar
    bar_length = 20
    used_bars = int((used_percent / 100) * bar_length)
    free_bars = bar_length - used_bars
    bar = "█" * used_bars + "░" * free_bars
    print(f"📈 Usage: [{bar}] {used_percent:.1f}%")

    # Warnings
    if used_percent > 90:
        print("⚠️  WARNING: Disk is over 90% full!")
    elif used_percent > 80:
        print("⚠️  NOTICE: Disk is over 80% full")
    else:
        print("✅ Disk space looks good!")

    print("\n" + "=" * 40)
    print("This is how Claude Desktop would see your disk space!")

if __name__ == "__main__":
    check_disk_space()
