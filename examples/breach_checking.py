"""
ShieldPass - Advanced Usage Examples

Demonstrates advanced features like breach checking and custom analysis.
"""

import sys
sys.path.append('..')
from main import (
    load_breach_data,
    check_breach,
    BREACH_FILE
)

print("=" * 60)
print("ShieldPass - Advanced Usage")
print("=" * 60)
print()

# Note: This example requires rockyou.txt to be present
if not BREACH_FILE.exists():
    print("⚠️  rockyou.txt not found!")
    print("   This example requires the breach database.")
    print("   Download rockyou.txt and place it in the project directory.")
    print()
    print("   The file can be found in common password lists or")
    print("   security testing datasets.")
    sys.exit(1)

# Example: Check if passwords are breached
print("Example: Breach Database Checking")
print("-" * 60)
print("Loading breach database (this may take a moment)...")
print()

# Load the breach database
load_breach_data()

# Test passwords
test_passwords = [
    "password123",
    "qwerty",
    "iloveyou",
    "xK9#mQ2$vL8@nP5*",  # Likely not breached
    "123456"
]

print(f"{'Password':<25} | {'Status':<20} | {'Occurrences'}")
print("-" * 70)

for pwd in test_passwords:
    is_breached, count = check_breach(pwd)
    if is_breached:
        status = "🚨 BREACHED"
        occurrences = f"{count:,}" if count else "Unknown"
    else:
        status = "✅ Not found"
        occurrences = "0"
    
    print(f"{pwd:<25} | {status:<20} | {occurrences}")

print()
print("=" * 60)
print("Tip: Always avoid passwords that appear in breach databases!")
print("=" * 60)
