# 🛡️ ShieldPass — Command‑Line Password Intelligence

Generate unbreakable passwords, audit real strength, and check against 14M+ breached credentials — privately, locally, and beautifully in your terminal.

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-black.svg)](#)
[![Privacy First](https://img.shields.io/badge/privacy-k--anonymity-success.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> No cloud. No tracking. No compromises.

---

## Why You'll Love It

- 🔐 Cryptographic generation with Python `secrets` (true randomness)
- 🧠 Smart scoring: Shannon entropy + `zxcvbn` + pattern detection
- 🔍 Private breach checks (k-anonymity; your input stays local)
- 🎨 Instant clarity: color-coded results and clean CLI UX

---

## Install & Run (10 seconds)

```bash
git clone https://github.com/Usero0/shieldpass.git
cd shieldpass
pip install zxcvbn  # Optional but recommended
python main.py
```

- Requirements: Python 3.7+
- Optional: `zxcvbn` (adds richer heuristic analysis)

---

## What It Can Do

### 1) Generate Passwords
- Random: choose from A–Z, a–z, 0–9, and symbols
- Pronounceable: memorable yet strong
- Passphrases: multi-word combos (needs `passphrase.txt`)

### 2) Analyze Security
Military-grade intel on any password:

```
Input: "P@ssw0rd123"
Output:
  ├─ Strength: Weak (42.3 bits entropy)
  ├─ Vulnerabilities: Sequential patterns detected
  ├─ Breach Status: Found in 14,231 breaches
  └─ Crack Time: 3 hours (GPU brute-force)
```

### 3) Scan Breaches
- Searches `rockyou.txt` (14M+ compromised passwords)
- k-anonymity keeps the original secret local
- Bloom filters for lightning-fast lookups
- Detects close variants (l33t, substitutions)

---

## Security Benchmarks (Understand the Score)

| Entropy Range | Rating | Meaning |
|--------------:|:------:|---------|
| < 28 bits | 🔴 Very Weak | Crackable in seconds |
| 28–35 bits | 🟠 Weak | Minutes to hours |
| 36–59 bits | 🟡 Fair | Days to weeks |
| 60–127 bits | 🟢 Good | Months to years |
| ≥ 128 bits | 🔵 Excellent | Practically unbreakable |

Pattern Detection Engine flags:
- Sequential: `abc`, `123`, `xyz`
- Repetitive: `aaa`, `111`, `!!!!!`
- Keyboard: `qwerty`, `asdf`, `zxcvbn`
- Dictionary: common words + l33t substitutions

---

## Usage Recipes (Copy & Paste)

```bash
# 1. Generate a strong random password
python main.py
# → Option [1] Generate Random Password
# → Enter desired length (16-20 recommended)
# → Select character types (all enabled for max strength)

# 2. Check if a password has been breached
python main.py
# → Option [2] Check Password Against Breach List
# → Paste your password to scan against 14M+ known breaches

# 3. Calculate password entropy
python main.py
# → Option [3] Check Password Entropy
# → Get Shannon entropy bits and strength rating
```

See more in examples:
- examples/basic_usage.py — getting started
- examples/breach_checking.py — advanced breach detection

---

## Bring Your Own Data (Optional)

Place these files in the project root to unlock extras:

| File | Purpose | Size |
|------|---------|------|
| `rockyou.txt` | Breach checking | ~140MB (14M passwords) |
| `passphrase.txt` | Passphrase generation | Varies |

---

## Project Layout

```
paswrd/
├── main.py                 # Core engine
├── requirements.txt        # Dependencies
├── LICENSE                 # MIT
└── examples/
    ├── basic_usage.py      # Getting started
    └── breach_checking.py  # Advanced breach detection
```

---

## Contributing

Got an idea or found a bug? Issues and PRs are welcome — this project thrives on community input.

---

## Ethical Use

ShieldPass exists for education and personal security improvement.
- Only test passwords you own
- Prefer a reputable password manager in production
- Use unique passwords per account
- Enable 2FA wherever possible

---

## Security Resources

- NIST Password Guidelines — https://pages.nist.gov/800-63-3/
- OWASP Authentication Cheatsheet — https://owasp.org/www-community/password-special-characters
- Have I Been Pwned — https://haveibeenpwned.com/

---

## Support Development

If ShieldPass helped you, consider supporting future work:

<details>
<summary>💰 Crypto Addresses (click to expand)</summary>

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

Every contribution fuels future updates. 🚀

---

MIT Licensed • Crafted with 💜 by [Usero0](https://github.com/Usero0) • If you found this useful, ⭐ the repo and share it!
