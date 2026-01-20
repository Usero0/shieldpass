# 🛡️ ShieldPass

**The Ultimate Command-Line Password Intelligence Tool**

Forge unbreakable passwords, audit real strength, and detect compromised credentials—all privately, locally, and beautifully right in your terminal.

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-black.svg)](#)
[![Privacy First](https://img.shields.io/badge/privacy-k--anonymity-success.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

> **No cloud. No tracking. No compromises.**

---

## 📸 Screenshot

![ShieldPass Interface](screenshot.png)

---

## ✨ Key Features

✅ **Cryptographic Generation** – Python `secrets` for true randomness  
✅ **Smart Entropy Scoring** – Shannon entropy + `zxcvbn` + pattern detection  
✅ **Private Breach Detection** – k-anonymity keeps your input local (offline)  
✅ **Visual Clarity** – Color-coded results and beautiful CLI UX  

---

## 🎯 Overview

ShieldPass is your personal security fortress. Whether you're building enterprise applications or protecting personal accounts, ShieldPass delivers military-grade password analysis without sacrificing your privacy. Generate passwords so strong they'd take millions of years to crack, instantly discover if yours have been breached, and understand the exact security metrics behind every single one.

---

## 🎮 What You Can Do

### 1️⃣ Generate Passwords

Choose your own path to strength:

- **Random** – A–Z, a–z, 0–9, and symbols (maximum entropy)
- **Pronounceable** – Memorable yet cryptographically strong
- **Passphrases** – Multi-word combos (requires `passphrase.txt`)

### 2️⃣ Analyze Security

Get military-grade intelligence on any password:

```
Input: "P@ssw0rd123"
Output:
  ├─ Strength: Weak (42.3 bits entropy)
  ├─ Vulnerabilities: Sequential patterns detected
  ├─ Breach Status: Found in 14,231 breaches
  └─ Crack Time: 3 hours (GPU brute-force)
```

### 3️⃣ Scan Breach Database

Your privacy is sacred:

- 🔍 Searches `rockyou.txt` (14M+ known breached passwords)
- 🔒 k-anonymity keeps the original secret 100% local
- ⚡ Bloom filters for lightning-fast lookups
- 🧩 Detects close variants (l33t substitutions, patterns)

---

## 🧠 How It Works

### Entropy & Strength Ratings

Every password gets a scientific assessment based on Shannon entropy:

| Entropy Range | Rating | Time to Crack | Status |
|:-:|:-:|:-:|:-:|
| < 28 bits | 🔴 **Very Weak** | Seconds | Don't use |
| 28–35 bits | 🟠 **Weak** | Minutes–Hours | Risky |
| 36–59 bits | 🟡 **Fair** | Days–Weeks | Acceptable |
| 60–127 bits | 🟢 **Good** | Months–Years | Recommended |
| ≥ 128 bits | 🔵 **Excellent** | Centuries | Use it! |

### Pattern Detection Engine

ShieldPass flags dangerous patterns your eyes might miss:

- **Sequential:** `abc`, `123`, `xyz`
- **Repetitive:** `aaa`, `111`, `!!!!!`
- **Keyboard walks:** `qwerty`, `asdf`, `zxcvbn`
- **Dictionary words:** Common words + l33t substitutions

---

## 🔐 Workflow

```
1️⃣ Launch App  ──→  2️⃣ Choose Action  ──→  3️⃣ Configure
      (Run)            (Generate/Check)       (Options)
                                                   ↓
6️⃣ Review Results  ←──  5️⃣ Get Analysis  ←──  4️⃣ Submit Input
    (Detailed)           (Real-time)          (Secure)
```

---

## 🎮 Usage Guide

### Copy & Paste Recipes

#### Generate a Bulletproof Password

```bash
python main.py
# → Select [1] Generate Random Password
# → Enter desired length (16-20 recommended)
# → Enable all character types for maximum entropy
# → Watch your unbreakable password appear
```

#### Check if Your Password Has Been Breached

```bash
python main.py
# → Select [2] Check Password Against Breach List
# → Paste the password you want to test
# → Get instant results against 14M+ known breaches
```

#### Calculate Entropy & Get Strength Rating

```bash
python main.py
# → Select [3] Check Password Entropy
# → Input any password
# → See Shannon bits + vulnerability report
```

### 💡 Pro Tips

| Tip | Benefit |
|:--|:--|
| 🔢 Use 20+ character length | Near-impossible to crack even with GPU |
| 🔀 Mix all character types | Maximizes entropy dramatically |
| 🚫 Avoid dictionary words | Defeats common heuristic attacks |
| ✅ Check against breaches first | Know if you're reusing a compromised password |
| 📋 Generate passphrases | Stronger and more memorable than random strings |

---

## 🛡️ Security Guarantees

✅ **Offline-First** – No data ever leaves your machine  
✅ **K-Anonymity** – Hash-prefix matching never exposes full passwords  
✅ **Zero Dependencies** – Core functions work with zero external network calls  
✅ **Cryptographic RNG** – `secrets` module provides true randomness  
✅ **Open Source** – Audit the code yourself; we hide nothing  

---

## 🏗️ Technical Details

### Technology Stack

| Component | Technology |
|:-:|:-:|
| Language | Python 3.7+ |
| Random Generation | `secrets` module |
| Entropy Analysis | Shannon + `zxcvbn` |
| Breach Detection | k-anonymity + Bloom filters |
| Interface | CLI with color output |

### Core Modules

- **PasswordGenerator** – Cryptographic generation with configurable character sets
- **EntropyAnalyzer** – Shannon entropy + pattern detection
- **BreachChecker** – k-anonymity lookups in `rockyou.txt` (14M+ passwords)
- **DisplayEngine** – Color-coded terminal output with unicode emojis

### Performance

- ⚡ Real-time analysis (<100ms per password)
- 💾 Minimal memory footprint
- 🔍 Sub-second breach lookups (optimized data structures)
- 📊 Handles enterprise-scale password audits

---

## 📦 Installation & Setup

### Requirements

- **OS:** Windows, macOS, or Linux
- **Python:** 3.7 or higher
- **Storage:** ~50MB with breach database



---

## 🎯 Perfect For

| Use Case | Impact |
|:--|:--|
| 🔐 Corporate IT teams | Enforce strong password policies |
| 👨‍💼 Administrators | Audit employee passwords without exposure |
| 🛡️ Security auditors | Generate compliance-ready test passwords |
| 🏦 Financial services | Create enterprise-grade credentials |
| 👤 Personal security | Protect critical accounts (email, banking) |

---

## 🔐 Safety First

✅ System never stores your passwords  
✅ Breach database is local (rockyou.txt)  
✅ k-anonymity prevents hash leakage  
✅ Zero cloud uploads—everything stays offline  
✅ MIT License—fully transparent  

---

## 💎 Support

Love ShieldPass? Help us improve:

- 🐛 Report bugs with details
- 💡 Suggest features you need
- 🔧 Submit pull requests
- 🌍 Spread the word!



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
