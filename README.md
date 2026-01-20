# 🛡️ ShieldPass — Password Intelligence Unleashed

> **Where cryptography meets elegance.** Generate fortress-grade passwords, uncover hidden vulnerabilities, and scan against 14M+ breached credentials — all in your terminal, with zero compromise on privacy.

<div align="center">

![ShieldPass Demo](screenshot.png)

[![Python 3.7+](https://img.shields.io/badge/python-3.7%2B-blue.svg)](https://www.python.org/)
[![CLI](https://img.shields.io/badge/interface-CLI-black.svg)](#)
[![Privacy First](https://img.shields.io/badge/privacy-k--anonymity-success.svg)](#)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

**No cloud · No tracking · No compromises**

</div>

---

## ✨ Why ShieldPass?

Tired of weak passwords and corporate password managers tracking your every move? ShieldPass brings **military-grade security** to your fingertips, running entirely offline:

- 🔐 **Cryptographic Generation** — True randomness via Python `secrets`
- 🧠 **Intelligent Strength Analysis** — Shannon entropy + `zxcvbn` + pattern detection
- 🔍 **Private Breach Scanning** — k-anonymity ensures your secrets stay *your* secrets
- 🎨 **Beautiful UX** — Color-coded insights and crystal-clear CLI design

---

## 🚀 Get Started in 10 Seconds

```bash
git clone https://github.com/Usero0/shieldpass.git
cd shieldpass
pip install zxcvbn  # Optional but recommended
python main.py
```

**Requirements:** Python 3.7+ | **Optional:** `zxcvbn` (unlocks heuristic superpowers)

---

## 🎯 What Can You Do?

### 1️⃣ Generate Passwords
Pick your poison:
- **Random** — Full alphabet (A–Z, a–z, 0–9, symbols)
- **Pronounceable** — Easy to remember, hard to crack
- **Passphrase** — Multi-word masterpieces (requires `passphrase.txt`)

### 2️⃣ Analyze Security Like a Pro
Get crystal-clear intelligence on *any* password:

```
Input: "P@ssw0rd123"
Output:
  ├─ Strength: Weak (42.3 bits entropy)
  ├─ Vulnerabilities: Sequential patterns detected
  ├─ Breach Status: Found in 14,231 breaches
  └─ Crack Time: 3 hours (GPU brute-force)
```

### 3️⃣ Scan the Breach Underground
Tap into our **14M+ compromised password database** with privacy intact:
- Lightning-fast Bloom filter lookups
- k-anonymity: your secret never leaves your machine
- Detects sneaky variants (l33t speak, substitutions)
- Built on `rockyou.txt` breach corpus

---

## 📊 The Strength Scale (Your Cheat Sheet)

| Entropy | Rating | What It Means |
|:-------:|:------:|---------------|
| < 28 bits | 🔴 **Very Weak** | Seconds to crack |
| 28–35 bits | 🟠 **Weak** | Minutes–hours |
| 36–59 bits | 🟡 **Fair** | Days–weeks |
| 60–127 bits | 🟢 **Good** | Months–years |
| ≥ 128 bits | 🔵 **Excellent** | Virtually unbreakable |

**Pattern Detection Red Flags:**
- Sequential: `abc`, `123`, `xyz` ❌
- Repetitive: `aaa`, `111`, `!!!!!` ❌
- Keyboard walks: `qwerty`, `asdf`, `zxcvbn` ❌
- Dictionary words + l33t tricks: `P@ssw0rd` ❌

---

## 💡 Common Use Cases (Copy & Paste)

```bash
# 1️⃣ Generate a fortress-grade password
python main.py
# → Select [1] Generate Random Password
# → Enter desired length (16-20 chars recommended for sweet spot)
# → Enable all character types for maximum entropy

# 2️⃣ Check if your password is in the wild
python main.py
# → Select [2] Check Password Against Breach List
# → Scan against 14M+ known compromised passwords

# 3️⃣ Measure password strength
python main.py
# → Select [3] Check Password Entropy
# → See Shannon entropy bits + vulnerability report
```

📚 **Want more?** Check out [examples/basic_usage.py](examples/basic_usage.py) and [examples/breach_checking.py](examples/breach_checking.py)

---

## 📦 Optional Superpowers (Bring Your Own Data)

Place these files in the root directory to unlock advanced features:

| File | Purpose | Size |
|:-----|:--------|-----:|
| `rockyou.txt` | 14M compromised passwords (breach detection) | ~140MB |
| `passphrase.txt` | Custom wordlist for passphrase generation | Variable |

---

## 🗂️ Project Structure

```
paswrd/
├── main.py                     # The engine that powers it all
├── requirements.txt            # Dependencies
├── LICENSE                     # MIT License
├── screenshot.png              # Visual demo
└── examples/
    ├── basic_usage.py          # Getting started guide
    └── breach_checking.py      # Advanced breach detection
```

---

## 🤝 Contributing

Have a brilliant idea? Found a bug? **We'd love your input!** Issues and pull requests are always welcome — this project thrives on community collaboration.

---

## ⚖️ Ethical Usage Commitment

ShieldPass is built for **education and personal security hardening** — use it responsibly:

✅ Test passwords you own or have explicit permission to test  
✅ Use ShieldPass insights to build stronger security habits  
✅ Combine with a password manager for production use  
✅ Create unique passwords for every account  
✅ Enable 2FA/MFA on critical accounts

---

## 📚 Security Learning Resources

- [NIST 800-63B](https://pages.nist.gov/800-63-3/) — U.S. government password guidelines
- [OWASP Authentication Cheatsheet](https://owasp.org/www-community/password-special-characters) — Security best practices
- [Have I Been Pwned](https://haveibeenpwned.com/) — Check if your accounts are compromised

---

## 💝 Support This Project

If ShieldPass helped you build better security habits, consider supporting ongoing development:

<details>
<summary>🪙 <strong>Crypto Donations</strong> (click to expand)</summary>

Love what we do? You can fuel future updates with crypto:

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

Every contribution accelerates feature releases. 🚀

</details>

---

## 📝 License & Authorship

<div align="center">

**MIT License** • Built with 💜 by [Usero0](https://github.com/Usero0)

If ShieldPass helped you, please **⭐ star this repository** and share it with others who care about digital security!

</div>
