# 🛡️ ShieldPass

> Your terminal-based guardian for password security – generate bulletproof passwords, analyze vulnerabilities, and check against 14M+ breached credentials, all with military-grade cryptography.

## ⚡ What Makes ShieldPass Different

**Four Superpowers in One Tool:**
- 🔐 **Cryptographic Generation** – Python's `secrets` module creates truly random passwords (no pseudo-random tricks)
- 🧠 **Intelligent Analysis** – Shannon entropy + zxcvbn + pattern detection = comprehensive strength scoring
- 🔍 **Privacy-First Breach Checking** – k-anonymity ensures your passwords never leave your machine
- 🎨 **Beautiful Terminal UI** – Color-coded security levels make complex data instantly understandable

## 🎬 Quick Start

```bash
git clone https://github.com/Usero0/shieldpass.git
cd shieldpass
pip install zxcvbn  # Optional but recommended
python main.py
```

**Requirements:** Python 3.7+ | Optional: `zxcvbn` for enhanced analysis

## 🔧 Core Features

### Password Generator
Choose your weapon:
- **Random**: Fully customizable character sets (A-Z, a-z, 0-9, symbols)
- **Pronounceable**: Memory-friendly passwords that still pack a punch
- **Passphrases**: Multi-word combinations (requires `passphrase.txt`)

### Security Analyzer
Get military-grade intel on any password:
```
Input: "P@ssw0rd123"
Output:
  ├─ Strength: Weak (42.3 bits entropy)
  ├─ Vulnerabilities: Sequential patterns detected
  ├─ Breach Status: Found in 14,231 breaches
  └─ Crack Time: 3 hours (GPU brute-force)
```

### Breach Database Scanner
- Searches **rockyou.txt** (14M+ compromised passwords)
- **k-anonymity** protocol protects your privacy
- Bloom filters enable lightning-fast lookups
- Discovers similar variations (l33tspeak, substitutions)

## 📊 Security Metrics Explained

| Entropy Range | Rating | Meaning |
|--------------|--------|---------|
| < 28 bits | 🔴 Very Weak | Crackable in seconds |
| 28-35 bits | 🟠 Weak | Minutes to hours |
| 36-59 bits | 🟡 Fair | Days to weeks |
| 60-127 bits | 🟢 Good | Months to years |
| ≥ 128 bits | 🔵 Excellent | Practically unbreakable |

**Pattern Detection Engine:**
- Sequential: `abc`, `123`, `xyz`
- Repetitive: `aaa`, `111`, `!!!!!`
- Keyboard: `qwerty`, `asdf`, `zxcvbn`
- Dictionary: Common words + l33t substitutions

## 📁 Optional Wordlists

Place these files in the project root for enhanced features:

| File | Purpose | Size |
|------|---------|------|
| `rockyou.txt` | Breach checking | ~140MB (14M passwords) |
| `passphrase.txt` | Passphrase generation | Varies |

## 🎯 Real-World Use Cases

```bash
# Scenario 1: Generate a password for your bank
$ python main.py → Option 1 → Length 20 → All character types

# Scenario 2: Check if your current password is safe
$ python main.py → Option 2 → Enter password → Get full security audit

# Scenario 3: Create memorable passphrase
$ python main.py → Option 1 → Passphrase mode → 4 words
```

## 🏗️ Architecture

```
paswrd/
├── main.py                 # Core engine
├── requirements.txt        # Dependencies
├── LICENSE                 # MIT
└── examples/
    ├── basic_usage.py      # Getting started
    └── breach_checking.py  # Advanced breach detection
```

## 🤝 Contributing

Got ideas? Found a bug? PRs and issues are welcome! This project thrives on community input.

## ⚠️ Ethical Use

ShieldPass is designed for **educational purposes** and **personal security enhancement**. Key principles:
- Never test passwords you don't own
- Use a reputable password manager for production environments
- Generate unique passwords for every account
- Enable 2FA wherever possible

## 🔗 Security Resources

- [NIST Password Guidelines](https://pages.nist.gov/800-63-3/) – Official US standards
- [OWASP Authentication Cheatsheet](https://owasp.org/www-community/password-special-characters) – Industry best practices
- [Have I Been Pwned](https://haveibeenpwned.com/) – Check if your email appeared in breaches

## 💎 Support Development

Building security tools takes time and coffee. If ShieldPass helped you, consider supporting:

<details>
<summary>💰 Crypto Addresses (Click to expand)</summary>

**Bitcoin (BTC)**
```
bc1qr4dtngl00cl7wcm3kaglyt624w2wp6rk0j8sn5
```

**Ethereum (ETH)**
```
0x84b867DE6f369b75054Be91E98Ad8EBa6F5C5A57
```

**Solana (SOL)**
```
HUyxkPgF2ZTuAuihZmop1AGKBJZVZG5N4iUZMVurQ7oM
```

</details>

Every contribution fuels future updates! 🚀

---

**MIT Licensed** | Crafted with 💜 by [Usero0](https://github.com/Usero0) | Star ⭐ if you find this useful!
