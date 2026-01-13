"""
ShieldPass - Basic Usage Examples

This file demonstrates basic usage of ShieldPass functions programmatically.
"""

import sys
sys.path.append('..')
from main import (
    generate_password,
    calculate_entropy,
    analyze_password_strength,
    check_common_patterns
)

# Example 1: Generate a secure password
print("=" * 60)
print("Example 1: Generate Secure Passwords")
print("=" * 60)

# Generate a 16-character password with all character types
password = generate_password(
    length=16,
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_special=True
)
print(f"Generated password: {password}")
print(f"Length: {len(password)}")
print()

# Generate a password with only letters and digits
simple_password = generate_password(
    length=12,
    use_lowercase=True,
    use_uppercase=True,
    use_digits=True,
    use_special=False
)
print(f"Simple password (no special chars): {simple_password}")
print()

# Example 2: Calculate entropy
print("=" * 60)
print("Example 2: Calculate Password Entropy")
print("=" * 60)

test_passwords = [
    "password123",
    "P@ssw0rd!",
    "Tr0ub4dor&3",
    "correct horse battery staple",
    "xK9#mQ2$vL8@nP5*"
]

for pwd in test_passwords:
    entropy = calculate_entropy(pwd)
    print(f"Password: {pwd:30} | Entropy: {entropy:.2f} bits")
print()

# Example 3: Analyze password strength
print("=" * 60)
print("Example 3: Analyze Password Strength")
print("=" * 60)

test_password = "MyP@ssw0rd2024!"
result = analyze_password_strength(test_password)

print(f"Password: {test_password}")
print(f"Entropy: {result['entropy']:.2f} bits")
print(f"Strength Level: {result['strength']}")
print(f"Has patterns: {result['has_patterns']}")
if result['warnings']:
    print(f"Warnings: {', '.join(result['warnings'])}")
print()

# Example 4: Check for common patterns
print("=" * 60)
print("Example 4: Pattern Detection")
print("=" * 60)

pattern_tests = [
    ("abc123", "Sequential characters"),
    ("password", "Common word"),
    ("aaabbb", "Repeated characters"),
    ("qwerty", "Keyboard pattern"),
    ("xK9#mQ2$", "Random (no obvious pattern)")
]

for pwd, description in pattern_tests:
    patterns = check_common_patterns(pwd)
    has_pattern = len(patterns) > 0
    print(f"{description:25} | Password: {pwd:15} | Pattern found: {has_pattern}")
    if patterns:
        print(f"  └─ Detected: {', '.join(patterns)}")
print()

# Example 5: Security levels comparison
print("=" * 60)
print("Example 5: Security Levels Comparison")
print("=" * 60)

passwords_by_strength = [
    ("123456", "Very Weak"),
    ("password", "Weak"),
    ("Pass1234", "Fair"),
    ("MyP@ss2024", "Good"),
    ("xK9#mQ2$vL8@nP5*wR7!", "Excellent")
]

print(f"{'Password':<25} | {'Expected':<15} | {'Entropy':<12} | {'Actual'}")
print("-" * 75)

for pwd, expected in passwords_by_strength:
    result = analyze_password_strength(pwd)
    entropy = result['entropy']
    actual = result['strength']
    print(f"{pwd:<25} | {expected:<15} | {entropy:>6.2f} bits | {actual}")
print()

print("=" * 60)
print("Examples completed!")
print("=" * 60)
