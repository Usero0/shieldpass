import math
import random
import secrets
import string
import hashlib
import struct
import urllib.request
import urllib.error
from collections import defaultdict
from pathlib import Path
import time
import re
from typing import Optional, List, Dict, Tuple, Any
try:
    from zxcvbn import zxcvbn
    HAS_ZXCVBN = True
except ImportError:
    HAS_ZXCVBN = False
    zxcvbn = None

# ANSI Color codes
class Colors:
    """ANSI color codes for terminal output."""
    BLACK = "\033[0;30m"
    RED = "\033[0;31m"
    BRED = "\033[1;31m"
    GREEN = "\033[0;32m"
    BGREEN = "\033[1;32m"
    YELLOW = "\033[0;33m"
    BYELLOW = "\033[1;33m"
    BLUE = "\033[0;34m"
    BBLUE = "\033[1;34m"
    PURPLE = "\033[0;35m"
    BPURPLE = "\033[1;35m"
    CYAN = "\033[0;36m"
    BCYAN = "\033[1;36m"
    WHITE = "\033[0;37m"
    NC = "\033[00m"  # No Color

# Backwards compatibility - use Color class attributes
black = Colors.BLACK
red = Colors.RED
bred = Colors.BRED
green = Colors.GREEN
bgreen = Colors.BGREEN
yellow = Colors.YELLOW
byellow = Colors.BYELLOW
blue = Colors.BLUE
bblue = Colors.BBLUE
purple = Colors.PURPLE
bpurple = Colors.BPURPLE
cyan = Colors.CYAN
bcyan = Colors.BCYAN
white = Colors.WHITE
nc = Colors.NC

logo = f"""

{bpurple}███████╗██╗  ██╗██╗███████╗██╗     ██████╗     ██████╗  █████╗ ███████╗███████╗                            
{purple}██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗    ██╔══██╗██╔══██╗██╔════╝██╔════╝                     
{bpurple}███████╗███████║██║█████╗  ██║     ██║  ██║    ██████╔╝███████║███████╗███████╗
{purple}╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║    ██╔═══╝ ██╔══██║╚════██║╚════██║
{bpurple}███████║██║  ██║██║███████╗███████╗██████╔╝    ██║     ██║  ██║███████║███████║
{purple}╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝     ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝

"""

# ============================================================================
# CONFIGURATION & CONSTANTS
# ============================================================================

# Character sets for password generation
SPECIAL_CHARACTERS = "!@#$%^&*"
PUNCTUATION_SET = set(string.punctuation)
EXTRA_PUNCT_SET = PUNCTUATION_SET - set(SPECIAL_CHARACTERS)

# File paths for breach data and wordlists
BREACH_FILE = Path("rockyou.txt")  # Breach password database
WORDLIST_FILE = Path("passphrase.txt")  # Wordlist for passphrase generation
BLOOM_FILE = Path("breach_bloom.bin")  # Bloom filter cache file

# Password constraints
MIN_PASSWORD_LENGTH = 5
MAX_PASSWORD_LENGTH = 128
MIN_PASSPHRASE_WORDS = 4
MAX_SIMILAR_RESULTS = 5000

# Global caches (lazy-loaded)
BREACH_CACHE = None  # In-memory k-anonymity index: SHA1 prefix -> suffix set
BLOOM_FILTER = None  # Bloom filter instance for fast breach lookups

# Time thresholds for security assessment (in seconds)
SECURITY_THRESHOLDS = {
    "critical": 3600,           # < 1 hour
    "dangerous": 86400,         # < 1 day
    "weak": 2592000,            # < 30 days
    "fair": 31536000,           # < 1 year
    "good": 315360000,          # < 10 years
    "excellent": 3153600000,    # < 100 years
}

# Password strength levels
STRENGTH_LEVELS = [
    (25, "Very Weak", red),
    (50, "Weak", red),
    (70, "Fair", yellow),
    (85, "Strong", green),
    (float('inf'), "Very Strong", bgreen),
]

# Entropy thresholds
ENTROPY_THRESHOLDS = {
    "low": 40,
    "moderate": 60,
    "high": 80,
}

COMMON_PATTERNS = [
    "password", "Password", "PASSWORD", "password123", "Password123",
    "123456", "12345678", "123456789", "1234567890",
    "qwerty", "QWERTY", "qwerty123",
    "abc123", "ABC123",
    "111111", "000000",
    "welcome", "Welcome", "welcome123",
    "admin", "Admin", "admin123",
    "letmein", "Letmein",
    "monkey", "dragon", "master",
    "123123", "654321",
    "passw0rd", "Passw0rd",
]

# Phonetic patterns for pronounceable passwords
VOWELS = "aeiou"
CONSONANTS = "bcdfghjklmnprstvwxyz"
# Avoid confusing consonants in some patterns
CLEAR_CONSONANTS = "bcdfghjklmnprstvwxz"
# Common syllable patterns
SYLLABLE_PATTERNS = [
    "cv",   # consonant-vowel (ba, ko, tu)
    "cvc",  # consonant-vowel-consonant (bat, log, pen)
    "ccv",  # consonant-consonant-vowel (bra, sto, gla)
    "cvcc", # consonant-vowel-consonant-consonant (best, land)
]


def prompt_yes_no(message: str) -> bool:
    """Prompt user for yes/no confirmation.
    
    Args:
        message: The message to display
        
    Returns:
        True if user answers 'y' or 'yes', False otherwise
    """
    while True:
        answer = input(f"{purple}{message} (y/n): {nc}").strip().lower()
        if answer in {"y", "yes", "n", "no", ""}:
            return answer in {"y", "yes"}
        print(f"{red}Please enter 'y' or 'n'.{nc}")


def generate_password(length: int, use_lowercase: bool = True, use_uppercase: bool = True, 
                      use_numbers: bool = True, use_special_chars: bool = False) -> str:
    """Generate a random password with specified character types.
    
    Args:
        length: Password length (must be valid)
        use_lowercase: Include lowercase letters (a-z)
        use_uppercase: Include uppercase letters (A-Z)
        use_numbers: Include digits (0-9)
        use_special_chars: Include special characters
        
    Returns:
        Generated password string
        
    Raises:
        ValueError: If no character types selected or length too short
    """
    pools = []
    if use_lowercase:
        pools.append(string.ascii_lowercase)
    if use_uppercase:
        pools.append(string.ascii_uppercase)
    if use_numbers:
        pools.append(string.digits)
    if use_special_chars:
        pools.append(SPECIAL_CHARACTERS)

    if not pools:
        raise ValueError("Select at least one character type.")
    if length < len(pools):
        raise ValueError(f"Length must be at least {len(pools)} to include every selected character type.")

    # Guarantee one character of each selected type
    password_chars = [secrets.choice(pool) for pool in pools]
    all_chars = "".join(pools)
    password_chars.extend(secrets.choice(all_chars) for _ in range(length - len(password_chars)))
    # Secure shuffle using SystemRandom
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)


def handle_generate_password() -> None:
    """Handle interactive password generation."""
    # Get password length with validation
    while True:
        try:
            length = int(input(f"{purple}Enter the desired password length ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH}): {nc}"))
            if MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
                break
            print(f"{red}Length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.{nc}")
        except ValueError:
            print(f"{red}Please enter a valid number for the length.{nc}")

    # Get character type preferences
    use_lowercase = prompt_yes_no("Include lowercase letters")
    use_uppercase = prompt_yes_no("Include uppercase letters")
    use_numbers = prompt_yes_no("Include numbers")
    use_special_chars = prompt_yes_no("Include special characters")

    try:
        password = generate_password(length, use_lowercase, use_uppercase, use_numbers, use_special_chars)
        print(f"\n{green}Generated password: {bgreen}{password}{nc}\n")
    except ValueError as exc:
        print(f"{red}{exc}{nc}")


def _load_breach_index(breach_file: Path = BREACH_FILE):
    """Load breach database into memory as k-anonymity index (prefix -> suffixes).
    
    Builds a dictionary mapping SHA1 prefixes (first 5 chars) to sets of suffixes.
    This enables fast lookups while keeping full hashes in memory.
    
    Returns:
        Dictionary of {prefix: set(suffixes)} or None if file doesn't exist
    """
    global BREACH_CACHE
    if BREACH_CACHE is not None:
        return BREACH_CACHE

    if not breach_file.exists():
        return None

    index = defaultdict(set)
    try:
        with breach_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for line in handle:
                pw = line.rstrip("\n\r")
                if not pw:
                    continue
                digest = hashlib.sha1(pw.encode("utf-8", errors="ignore")).hexdigest().upper()
                prefix, suffix = digest[:5], digest[5:]
                index[prefix].add(suffix)
    except (UnicodeDecodeError, IOError):
        return None

    BREACH_CACHE = index
    return index


def check_password_breach(password: str, breach_file: Path = BREACH_FILE):
    """Check if password is in breach list. Uses Bloom filter or in-memory cache."""
    # Prefer Bloom filter if available
    global BLOOM_FILTER
    digest = hashlib.sha1(password.encode("utf-8", errors="ignore")).hexdigest().upper()
    if BLOOM_FILTER is None:
        BLOOM_FILTER = load_bloom_filter(BLOOM_FILE)
    if BLOOM_FILTER is not None:
        if BLOOM_FILTER.check(digest):
            return True, "Password found (Bloom filter match)."
        else:
            return False, "Password not found (Bloom filter)."

    # Fallback to in-memory k-anon index (loads full breach list into memory)
    index = _load_breach_index(breach_file)
    prefix, suffix = digest[:5], digest[5:]
    if index is not None:
        bucket = index.get(prefix)
        if bucket and suffix in bucket:
            return True, "Password found in the breach list."
        return False, "Password not found in the breach list."

    # Final fallback: HIBP online k-anon
    hibp_ok, hibp_msg = hibp_check_password(password)
    return hibp_ok, hibp_msg


class BloomFilter:
    """Probabilistic data structure for fast membership testing.
    
    Uses multiple hash functions to efficiently check if a password hash exists
    in the breach database. May have false positives but never false negatives.
    Space-efficient alternative to storing all hashes in memory.
    """
    def __init__(self, size_bits: int, hash_count: int, bitarray: Optional[bytearray] = None):
        self.size_bits = size_bits
        self.hash_count = hash_count
        self.size_bytes = (size_bits + 7) // 8
        self.bits = bitarray if bitarray is not None else bytearray(self.size_bytes)

    def _indices(self, digest_hex: str):
        """Generate k hash indices for the given digest using salted SHA1."""
        for i in range(self.hash_count):
            h = hashlib.sha1((digest_hex + str(i)).encode("utf-8")).digest()
            idx = int.from_bytes(h[:8], "big") % self.size_bits
            yield idx

    def add(self, digest_hex: str):
        """Add a hash to the Bloom filter by setting k bits."""
        for idx in self._indices(digest_hex):
            byte_idx = idx // 8
            bit_idx = idx % 8
            self.bits[byte_idx] |= (1 << bit_idx)

    def check(self, digest_hex: str) -> bool:
        """Check if hash might exist in the filter (no false negatives)."""
        for idx in self._indices(digest_hex):
            byte_idx = idx // 8
            bit_idx = idx % 8
            if (self.bits[byte_idx] & (1 << bit_idx)) == 0:
                return False
        return True


def build_bloom_filter(breach_file: Path = BREACH_FILE, bloom_file: Path = BLOOM_FILE, size_bits: int = 64_000_000, hash_count: int = 7) -> Tuple[bool, str]:
    """Build and persist a Bloom filter from breach password list.
    
    Creates a space-efficient Bloom filter for fast breach lookups.
    Default configuration: ~30MB file size with ~1% false positive rate.
    
    Args:
        breach_file: Path to breach password list (one password per line)
        bloom_file: Output file for serialized Bloom filter
        size_bits: Bit array size (larger = fewer false positives)
        hash_count: Number of hash functions (k)
    
    Returns:
        Tuple of (success, message with stats including false positive rate)
    """
    if not breach_file.exists():
        return False, "Breach list file not found."

    # First pass: count total lines
    print(f"\n{cyan}[*] Counting passwords...{nc}")
    total_file_lines = 0
    try:
        with breach_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for _ in handle:
                total_file_lines += 1
    except Exception as e:
        return False, f"Error counting file: {e}"
    
    print(f"{cyan}[*] Building Bloom filter for {total_file_lines:,} passwords...{nc}")

    bf = BloomFilter(size_bits=size_bits, hash_count=hash_count)
    n = 0
    start_time = time.time()
    buffer_size = 100_000  # Show progress every 100k lines
    
    try:
        with breach_file.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_num, line in enumerate(handle, 1):
                pw = line.rstrip("\n\r")
                if not pw:
                    continue
                digest = hashlib.sha1(pw.encode("utf-8", errors="ignore")).hexdigest().upper()
                bf.add(digest)
                n += 1
                
                # Show progress every buffer_size lines
                if n % buffer_size == 0:
                    elapsed = time.time() - start_time
                    rate = n / elapsed if elapsed > 0 else 0
                    remaining = total_file_lines - n
                    eta = remaining / rate if rate > 0 else 0
                    
                    progress_pct = (n / total_file_lines * 100) if total_file_lines > 0 else 0
                    bar_length = 30
                    filled = int(bar_length * progress_pct / 100)
                    bar = f"{bgreen}{'█' * filled}{nc}{purple}{'░' * (bar_length - filled)}{nc}"
                    
                    print(f"\r{bar} {progress_pct:5.1f}% | {n:,}/{total_file_lines:,} | "
                          f"{rate:,.0f} pwd/s | ETA: {int(eta)}s", end="", flush=True)
                
    except Exception as e:
        return False, f"Error building Bloom filter: {e}"

    print()  # New line after progress bar
    
    try:
        print(f"{cyan}[*] Saving Bloom filter to disk...{nc}")
        with bloom_file.open("wb") as out:
            # header: magic, size_bits, hash_count
            out.write(b"BLMF")
            out.write(struct.pack("<Q", bf.size_bits))
            out.write(struct.pack("<I", bf.hash_count))
            out.write(bf.bits)
    except Exception as e:
        return False, f"Error saving Bloom filter: {e}"

    # Estimate false positive probability: p ≈ (1 - e^{-k*n/m})^k
    m = bf.size_bits
    k = bf.hash_count
    p = (1 - math.exp(-(k * n) / m)) ** k if m > 0 else 1.0
    total_time = time.time() - start_time
    return True, f"Bloom filter built: {bloom_file} (size ~{bf.size_bytes/1024/1024:.1f} MB, k={k}, entries={n:,}, p≈{p:.6f}, time={total_time:.1f}s)"



def load_bloom_filter(bloom_file: Path = BLOOM_FILE) -> Optional[BloomFilter]:
    """Load a previously built Bloom filter from disk.
    
    Returns:
        BloomFilter instance if file exists and is valid, None otherwise
    """
    if not bloom_file.exists():
        return None
    try:
        with bloom_file.open("rb") as inp:
            magic = inp.read(4)
            if magic != b"BLMF":
                return None
            size_bits = struct.unpack("<Q", inp.read(8))[0]
            hash_count = struct.unpack("<I", inp.read(4))[0]
            data = bytearray(inp.read())
            return BloomFilter(size_bits=size_bits, hash_count=hash_count, bitarray=data)
    except Exception:
        return None


def hibp_check_password(password: str) -> Tuple[bool, str]:
    """Check password against Have I Been Pwned using k-anonymity API.
    
    Uses the first 5 characters of the SHA1 hash to query the HIBP range API,
    preserving privacy by never sending the full password hash.
    
    Returns:
        Tuple of (breached, message)
    """
    try:
        digest = hashlib.sha1(password.encode("utf-8", errors="ignore")).hexdigest().upper()
        prefix, suffix = digest[:5], digest[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        req = urllib.request.Request(url, headers={"User-Agent": "ShieldPass/1.0"})
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode("utf-8", errors="ignore")
        for line in body.splitlines():
            parts = line.split(":")
            if len(parts) >= 1 and parts[0].strip().upper() == suffix:
                return True, "Password found via HIBP k-anon."
        return False, "Password not found via HIBP k-anon."
    except urllib.error.URLError:
        return False, "HIBP check unavailable (network error)."
    except Exception as e:
        return False, f"HIBP check error: {e}"




def estimate_charset_size(password: str) -> int:
    """Estimate the character set size used in a password.
    
    Analyzes password to determine how many unique character types it uses:
    lowercase (26), uppercase (26), digits (10), special chars, etc.
    Used for entropy calculation.
    
    Returns:
        Estimated total character set size
    """
    charset = 0
    if any(ch.islower() for ch in password):
        charset += 26
    if any(ch.isupper() for ch in password):
        charset += 26
    if any(ch.isdigit() for ch in password):
        charset += 10
    if any(ch in SPECIAL_CHARACTERS for ch in password):
        charset += len(SPECIAL_CHARACTERS)
    if any(ch in EXTRA_PUNCT_SET for ch in password):
        charset += len(EXTRA_PUNCT_SET)
    
    # Count unicode or other rare characters
    other_chars = {ch for ch in password if not (ch.isalnum() or ch in PUNCTUATION_SET)}
    charset += len(other_chars)
    return charset


def calculate_entropy(password: str) -> float:
    """Calculate Shannon entropy of password in bits.
    
    Entropy = length × log2(charset_size)
    Higher entropy = more random, harder to brute force.
    
    Returns:
        Entropy in bits
    """
    charset_size = estimate_charset_size(password)
    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def calculate_entropy_zxcvbn(password: str) -> Tuple[float, Optional[Any]]:
    """Calculate entropy using zxcvbn if available, otherwise use classic method.
    
    Returns:
        Tuple of (entropy_bits, zxcvbn_analysis_dict or None)
    """
    if not HAS_ZXCVBN or zxcvbn is None:
        # Fallback to classic method
        charset_size = estimate_charset_size(password)
        if charset_size == 0:
            return 0.0, None
        entropy = len(password) * math.log2(charset_size)
        return entropy, None
    
    try:
        analysis = zxcvbn(password)
        # zxcvbn score is 0-4, convert to estimated entropy
        # Score 4 = ~128 bits, Score 0 = ~0 bits (relative)
        guesses = analysis.get('guesses', 1)
        entropy_bits = float(math.log2(guesses)) if guesses > 0 else 0.0
        return entropy_bits, analysis
    except Exception as e:
        # If zxcvbn fails, fallback to classic method
        charset_size = estimate_charset_size(password)
        if charset_size == 0:
            return 0.0, None
        entropy = len(password) * math.log2(charset_size)
        return entropy, None


def estimate_effective_length(password: str) -> int:
    """Rough zxcvbn-like shrinkage: penalizes patterns, sequences, dictionaries and l33t."""
    base_len = len(password)
    penalty = 0

    # Common dictionaries
    for pat in COMMON_PATTERNS:
        if pat.lower() in password.lower():
            penalty += min(len(pat), 6)
            break

    # Detected patterns
    detected = detect_common_patterns(password)
    for group in detected:
        # penalize length of detected items
        for item in group.get("items", []):
            # extract possible substring
            m = re.search(r"'(.*?)'", item)
            if m:
                penalty += min(len(m.group(1)), 6)
            else:
                penalty += 3

    # Simple alphanumeric sequences
    if re.search(r"(?i)[a-z]{3,}", password):
        penalty += 2
    if re.search(r"\d{3,}", password):
        penalty += 2

    # Simple reversible l33t
    if re.search(r"[@$!1i0o3e4a5s7t]", password.lower()):
        penalty += 2

    effective = max(4, base_len - penalty)
    return effective


def estimate_effective_length_zxcvbn(password: str) -> Tuple[int, Optional[Any]]:
    """Estimate effective length using zxcvbn if available.
    
    Returns:
        Tuple of (effective_length, zxcvbn_analysis_dict or None)
    """
    if not HAS_ZXCVBN or zxcvbn is None:
        return estimate_effective_length(password), None
    
    try:
        analysis = zxcvbn(password)
        # Extract feedback and sequence for more accurate estimate
        sequences = analysis.get('sequence', [])
        score = analysis.get('score', 0)
        
        # Calculate effective length based on zxcvbn scoring
        base_len = len(password)
        # Score 0 = virtually nothing, 4 = maximum entropy
        # Map score to coefficient (0=10%, 4=100%)
        effectiveness = 0.1 + (score * 0.225)  # range [0.1, 1.0]
        effective = max(4, int(base_len * effectiveness))
        return effective, analysis
    except Exception as e:
        # If zxcvbn fails, use classic method
        return estimate_effective_length(password), None


def analyze_password_strength(password: str) -> dict:
    """Analyzes password strength and returns a detailed report."""
    if not password:
        return {"score": 0, "level": "Very Weak", "issues": ["Password is empty"], "suggestions": ["Enter a password"]}
    
    score = 0
    issues = []
    suggestions = []
    
    # Length check (0-35 points)
    length = len(password)
    if length < 6:
        score += length * 3
        issues.append(f"Password is too short ({length} characters)")
        suggestions.append("Use at least 12 characters for better security")
    elif length < 8:
        score += 18
        issues.append("Password is short")
        suggestions.append("Consider using at least 12 characters")
    elif length < 10:
        score += 25
    elif length < 12:
        score += 30
    elif length < 16:
        score += 33
    else:
        score += 35
    
    # Character variety (0-30 points)
    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in PUNCTUATION_SET for c in password)
    
    variety_count = sum([has_lower, has_upper, has_digit, has_special])
    # Base points for variety
    score += variety_count * 5
    # Bonus if all 4 types are present
    if variety_count == 4:
        score += 10
    
    if not has_lower:
        issues.append("No lowercase letters")
        suggestions.append("Add lowercase letters (a-z)")
    if not has_upper:
        issues.append("No uppercase letters")
        suggestions.append("Add uppercase letters (A-Z)")
    if not has_digit:
        issues.append("No numbers")
        suggestions.append("Add numbers (0-9)")
    if not has_special:
        issues.append("No special characters")
        suggestions.append(f"Add special characters ({SPECIAL_CHARACTERS})")
    
    # Check for common patterns (0-20 points penalty)
    is_common = False
    for pattern in COMMON_PATTERNS:
        if pattern in password or password in pattern:
            is_common = True
            issues.append(f"Contains common pattern: '{pattern}'")
            suggestions.append("Avoid common words and patterns")
            score -= 20
            break

    # Penalize advanced patterns (keyboard walks, dates, repetitions) using detect_common_patterns
    detected = detect_common_patterns(password)
    for group in detected:
        penalty = 10 if "High" in group.get("risk", "") else 5
        score -= penalty
        for item in group.get("items", []):
            issues.append(item)
    if detected:
        suggestions.append("Remove dates, keyboard walks, and predictable sequences")

    # Simple mangling detection: common word + digits/symbols suffix
    if re.search(r"(?i)(password|qwerty|admin|letmein|welcome)[0-9!@#$%^&*]+$", password):
        score -= 10
        issues.append("Looks like a common word with a simple suffix")
        suggestions.append("Use a random base word or passphrase instead of common roots")
    
    # Check for sequential characters (0-15 points penalty)
    sequential_count = 0
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            num_seq = int(password[i]), int(password[i+1]), int(password[i+2])
            if num_seq[1] - num_seq[0] == 1 and num_seq[2] - num_seq[1] == 1:
                sequential_count += 1
        elif password[i:i+3].isalpha():
            if ord(password[i+1]) - ord(password[i]) == 1 and ord(password[i+2]) - ord(password[i+1]) == 1:
                sequential_count += 1
    
    if sequential_count > 0:
        penalty = min(15, sequential_count * 5)
        score -= penalty
        issues.append(f"Contains {sequential_count} sequential pattern(s)")
        suggestions.append("Avoid sequential characters (abc, 123, etc.)")
    
    # Check for character repetition (0-15 points penalty)
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    
    if max_repeat >= 3:
        penalty = min(15, (max_repeat - 2) * 5)
        score -= penalty
        issues.append(f"Character repeated {max_repeat} times in a row")
        suggestions.append("Avoid repeating the same character multiple times")
    
    # Check for only numbers or only letters (0-15 points penalty)
    if password.isdigit():
        score -= 15
        issues.append("Password contains only numbers")
        suggestions.append("Mix numbers with letters and special characters")
    elif password.isalpha():
        score -= 15
        issues.append("Password contains only letters")
        suggestions.append("Add numbers and special characters")
    
    # Entropy bonus (0-15 points)
    entropy = calculate_entropy(password)
    if entropy >= 80:
        score += 15
    elif entropy >= 70:
        score += 12
    elif entropy >= 60:
        score += 10
    elif entropy >= 50:
        score += 7
    elif entropy >= 40:
        score += 5
    
    # Bonus for very long passwords (0-10 bonus points)
    if length >= 20:
        score += 10
    elif length >= 16:
        score += 7
    elif length >= 14:
        score += 4
    
    # Ensure score is within 0-100 range
    score = max(0, min(100, score))
    
    # Optional zxcvbn integration for more accurate scoring and segments
    zxcvbn_segments = []
    zxcvbn_score_map = {0: 15, 1: 35, 2: 55, 3: 75, 4: 95}
    try:
        import importlib
        zxcvbn_mod = importlib.import_module("zxcvbn")
        zres = zxcvbn_mod.zxcvbn(password)
        zscore_0_4 = zres.get("score", 0)
        # Blend our score with zxcvbn
        score = max(0, min(100, int((score + zxcvbn_score_map.get(zscore_0_4, 0)) / 2)))
        for m in zres.get("sequence", []):
            i = m.get("i")
            j = m.get("j")
            token = m.get("token", "")
            mtype = m.get("pattern", "")
            if isinstance(i, int) and isinstance(j, int):
                zxcvbn_segments.append({"start": i, "end": j, "token": token, "type": mtype})
    except Exception:
        pass

    # Determine strength level using thresholds
    level = "Very Weak"
    color = red
    for threshold, level_name, level_color in STRENGTH_LEVELS:
        if score < threshold:
            level = level_name
            color = level_color
            break
    
    # Add general suggestions if no specific issues
    if not suggestions:
        suggestions.append("Your password is strong!")
        if length < 16:
            suggestions.append("Consider making it even longer for maximum security")
    
    return {
        "score": score,
        "level": level,
        "color": color,
        "issues": issues,
        "suggestions": suggestions,
        "length": length,
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digit": has_digit,
        "has_special": has_special,
        "zxcvbn_segments": zxcvbn_segments,
    }


def handle_password_strength_analysis() -> None:
    password = input(f"{purple}Enter the password to analyze: {nc}")
    
    analysis = analyze_password_strength(password)
    
    print(f"\n{bpurple}{'='*60}{nc}")
    print(f"{bpurple}PASSWORD STRENGTH ANALYSIS{nc}")
    print(f"{bpurple}{'='*60}{nc}\n")
    
    # Score and level
    color = analysis['color']
    print(f"{purple}Score: {color}{analysis['score']}/100{nc}")
    print(f"{purple}Strength Level: {color}{analysis['level']}{nc}\n")
    
    # Password characteristics
    print(f"{cyan}Password Characteristics:{nc}")
    print(f"  Length: {analysis['length']} characters")
    print(f"  Lowercase letters: {'✓' if analysis['has_lower'] else '✗'}")
    print(f"  Uppercase letters: {'✓' if analysis['has_upper'] else '✗'}")
    print(f"  Numbers: {'✓' if analysis['has_digit'] else '✗'}")
    print(f"  Special characters: {'✓' if analysis['has_special'] else '✗'}")
    
    # Entropy
    entropy = calculate_entropy(password)
    print(f"\n{cyan}Entropy: {entropy:.2f} bits{nc}")
    
    # Issues found
    if analysis['issues']:
        print(f"\n{red}Issues Found:{nc}")
        for i, issue in enumerate(analysis['issues'], 1):
            print(f"  {red}[{i}] {issue}{nc}")
    else:
        print(f"\n{green}No issues found!{nc}")
    
    # Zxcvbn segments (if available)
    segments = analysis.get('zxcvbn_segments') or []
    if segments:
        print(f"\n{cyan}Weak Segments (zxcvbn):{nc}")
        for s in segments:
            start, end, token, typ = s['start'], s['end'], s['token'], s['type']
            print(f"  {purple}[{start}-{end}] {typ}: '{token}'{nc}")

    # Suggestions
    print(f"\n{yellow}Suggestions:{nc}")
    for i, suggestion in enumerate(analysis['suggestions'], 1):
        print(f"  {yellow}[{i}] {suggestion}{nc}")
    
    print(f"\n{bpurple}{'='*60}{nc}\n")


def format_time_duration(seconds: float) -> str:
    """Formats a duration in seconds to a human-readable string."""
    if not math.isfinite(seconds):
        return "> 1e308 seconds"
    if seconds < 0.001:
        return "< 1 millisecond"
    elif seconds < 1:
        return f"{seconds * 1000:.2f} milliseconds"
    elif seconds < 60:
        return f"{seconds:.2f} seconds"
    elif seconds < 3600:
        minutes = seconds / 60
        return f"{minutes:.2f} minutes"
    elif seconds < 86400:
        hours = seconds / 3600
        return f"{hours:.2f} hours"
    elif seconds < 31536000:
        days = seconds / 86400
        return f"{days:.2f} days"
    elif seconds < 3153600000:  # 100 years
        years = seconds / 31536000
        return f"{years:.2f} years"
    elif seconds < 31536000000:  # 1000 years
        centuries = seconds / 3153600000
        return f"{centuries:.2f} centuries"
    elif seconds < 31536000000000:  # 1 million years
        millennia = seconds / 31536000000
        return f"{millennia:.2f} millennia"
    else:
        millions_of_years = seconds / 31536000000000
        # Use scientific notation for extremely large numbers (> 1e15 million years)
        if millions_of_years > 1e15:
            return f"{millions_of_years:.2e} million years"
        else:
            return f"{millions_of_years:,.2f} million years"


HASH_SPEED_PROFILES = {
    "fast": [
        {"name": "Home Computer", "speed": 1_000_000, "description": "~1M H/s (fast hash)", "color": cyan},
        {"name": "Gaming PC (GPU)", "speed": 100_000_000, "description": "~100M H/s (fast hash)", "color": cyan},
        {"name": "Professional Rig", "speed": 1_000_000_000, "description": "~1B H/s (fast hash)", "color": yellow},
        {"name": "Supercomputer", "speed": 100_000_000_000, "description": "~100B H/s (fast hash)", "color": yellow},
        {"name": "Distributed Network", "speed": 1_000_000_000_000, "description": "~1T H/s (fast hash)", "color": red},
    ],
    "bcrypt12": [
        {"name": "Home Computer", "speed": 200, "description": "~200 H/s (bcrypt cost 12)", "color": cyan},
        {"name": "Gaming PC (GPU)", "speed": 3_000, "description": "~3K H/s (bcrypt cost 12)", "color": cyan},
        {"name": "Professional Rig", "speed": 20_000, "description": "~20K H/s (bcrypt cost 12)", "color": yellow},
        {"name": "Supercomputer", "speed": 200_000, "description": "~200K H/s (bcrypt cost 12)", "color": yellow},
        {"name": "Distributed Network", "speed": 2_000_000, "description": "~2M H/s (bcrypt cost 12)", "color": red},
    ],
    "argon2id": [
        {"name": "Home Computer", "speed": 100, "description": "~100 H/s (argon2id moderate)", "color": cyan},
        {"name": "Gaming PC (GPU)", "speed": 1_000, "description": "~1K H/s (argon2id moderate)", "color": cyan},
        {"name": "Professional Rig", "speed": 8_000, "description": "~8K H/s (argon2id moderate)", "color": yellow},
        {"name": "Supercomputer", "speed": 80_000, "description": "~80K H/s (argon2id moderate)", "color": yellow},
        {"name": "Distributed Network", "speed": 800_000, "description": "~0.8M H/s (argon2id moderate)", "color": red},
    ],
}


def calculate_crack_time(password: str, profile: str = "fast", bcrypt_cost: int = 12, argon_mem_kib: int = 65536, argon_iters: int = 2) -> dict:
    """Calculates crack time using selectable hash-speed profiles (fast/bcrypt/argon2) with param tweaks."""
    if not password:
        return {"combinations": 0, "scenarios": []}

    charset_size = estimate_charset_size(password)
    length = len(password)

    # Estimate effective length (zxcvbn-like) to account for patterns
    effective_length = estimate_effective_length(password)
    # Try to use zxcvbn for better estimate
    zxcvbn_effective, zxcvbn_data = estimate_effective_length_zxcvbn(password)
    # Use the most conservative estimate (lower = safer)
    effective_length = min(effective_length, zxcvbn_effective) if zxcvbn_data else effective_length

    # Calculate total possible combinations (effective)
    total_combinations = charset_size ** effective_length

    # Average case: need to try 50% of all combinations
    avg_combinations = total_combinations / 2

    scenarios = HASH_SPEED_PROFILES.get(profile, HASH_SPEED_PROFILES["fast"])

    # Tweaka i profili lenti in base ai parametri runtime
    adjusted = []
    if profile == "bcrypt12":
        scale = 2 ** (bcrypt_cost - 12)
        for s in scenarios:
            adjusted.append({**s, "speed": max(1, s["speed"] // scale)})
        scenarios = adjusted
    elif profile == "argon2id":
        # Scala linearmente su memoria e iterazioni
        mem_factor = argon_mem_kib / 65536
        iter_factor = argon_iters / 2
        scale = max(1, mem_factor * iter_factor)
        for s in scenarios:
            adjusted.append({**s, "speed": max(1, int(s["speed"] / scale))})
        scenarios = adjusted

    results = []
    for scenario in scenarios:
        time_seconds = avg_combinations / scenario["speed"]
        results.append({
            "name": scenario["name"],
            "description": scenario["description"],
            "time_seconds": time_seconds,
            "time_formatted": format_time_duration(time_seconds),
            "color": scenario["color"],
        })

    return {
        "charset_size": charset_size,
        "length": length,
        "effective_length": effective_length,
        "total_combinations": total_combinations,
        "avg_combinations": avg_combinations,
        "scenarios": results,
        "profile": profile,
        "bcrypt_cost": bcrypt_cost,
        "argon_mem_kib": argon_mem_kib,
        "argon_iters": argon_iters,
    }


def get_security_level(max_time_seconds: float) -> Tuple[str, str]:
    """Determine security level based on crack time.
    
    Args:
        max_time_seconds: Time in seconds to crack password
        
    Returns:
        Tuple of (security_level_string, color_code)
    """
    thresholds = [
        (SECURITY_THRESHOLDS["critical"], "CRITICAL - Very Easy to Crack", red),
        (SECURITY_THRESHOLDS["dangerous"], "DANGEROUS - Easy to Crack", red),
        (SECURITY_THRESHOLDS["weak"], "WEAK - Moderate Protection", yellow),
        (SECURITY_THRESHOLDS["fair"], "FAIR - Good for Low-Risk Use", yellow),
        (SECURITY_THRESHOLDS["good"], "GOOD - Strong Protection", green),
        (SECURITY_THRESHOLDS["excellent"], "EXCELLENT - Very Strong", green),
        (float('inf'), "MAXIMUM - Virtually Uncrackable", bgreen),
    ]
    
    for threshold, level, color in thresholds:
        if max_time_seconds < threshold:
            return level, color
    
    return "MAXIMUM - Virtually Uncrackable", bgreen


def handle_crack_time_test() -> None:
    password = input(f"{purple}Enter the password to test crack time: {nc}")
    
    if not password:
        print(f"{red}Password cannot be empty.{nc}")
        return
    
    profile_choice = input(f"{bpurple}Hash profile [fast/bcrypt12/argon2id] (default fast): {nc}").strip().lower() or "fast"
    if profile_choice not in HASH_SPEED_PROFILES:
        print_warning("Unknown profile, using fast")
        profile_choice = "fast"

    bcrypt_cost = 12
    argon_mem_kib = 65536
    argon_iters = 2

    if profile_choice == "bcrypt12":
        try:
            bcrypt_cost = int(input(f"{bpurple}bcrypt cost (10-16, default 12): {nc}") or 12)
            bcrypt_cost = min(max(bcrypt_cost, 10), 16)
        except ValueError:
            bcrypt_cost = 12
            print_warning("Invalid cost, using 12")
    elif profile_choice == "argon2id":
        try:
            argon_mem_kib = int(input(f"{bpurple}argon2 memory KiB (32768-262144, default 65536): {nc}") or 65536)
            argon_mem_kib = min(max(argon_mem_kib, 32768), 262144)
        except ValueError:
            argon_mem_kib = 65536
            print_warning("Invalid memory, using 65536")
        try:
            argon_iters = int(input(f"{bpurple}argon2 iterations (1-6, default 2): {nc}") or 2)
            argon_iters = min(max(argon_iters, 1), 6)
        except ValueError:
            argon_iters = 2
            print_warning("Invalid iterations, using 2")

    result = calculate_crack_time(password, profile=profile_choice, bcrypt_cost=bcrypt_cost, argon_mem_kib=argon_mem_kib, argon_iters=argon_iters)
    
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}BRUTE FORCE CRACK TIME ANALYSIS{nc}")
    print(f"{bpurple}{'='*70}{nc}\n")
    
    # Password info
    print(f"{cyan}Password Information:{nc}")
    print(f"  Length: {result['length']} characters")
    print(f"  Character Set Size: {result['charset_size']} possible characters")
    print(f"  Effective Length (pattern-adjusted): {result['effective_length']}")
    
    # Use scientific notation for extremely large numbers
    if result['total_combinations'] > 1e50:
        print(f"  Total Combinations: {result['total_combinations']:.2e}")
    else:
        print(f"  Total Combinations: {result['total_combinations']:,.0f}")
    
    if result['avg_combinations'] > 1e50:
        print(f"  Average Attempts Needed: {result['avg_combinations']:.2e}")
    else:
        print(f"  Average Attempts Needed: {result['avg_combinations']:,.0f}")
    
    # Security assessment based on strongest realistic attack (Supercomputer)
    supercomputer_time = result['scenarios'][3]['time_seconds']
    security_level, security_color = get_security_level(supercomputer_time)
    
    print(f"\n{cyan}Security Level: {security_color}{security_level}{nc}  {purple}(profile: {result['profile']}, eff len: {result['effective_length']}, cost: {result.get('bcrypt_cost', '')}){nc}")
    
    # Crack time scenarios
    print(f"\n{bpurple}Time to Crack (Average Case):{nc}\n")
    
    for scenario in result['scenarios']:
        color = scenario['color']
        print(f"{purple}├─ {scenario['name']} {color}{scenario['description']}{nc}")
        print(f"{purple}│  └─ Time: {color}{scenario['time_formatted']}{nc}\n")
    
    # Recommendations
    print(f"{yellow}Recommendations:{nc}")
    if supercomputer_time < 86400:  # Less than 1 day
        print(f"  {red}[!] This password can be cracked very quickly!{nc}")
        print(f"  {yellow}[→] Use a much longer password (16+ characters){nc}")
        print(f"  {yellow}[→] Mix uppercase, lowercase, numbers, and special characters{nc}")
    elif supercomputer_time < 31536000:  # Less than 1 year
        print(f"  {yellow}[!] This password could be cracked by determined attackers{nc}")
        print(f"  {yellow}[→] Consider making it longer (14+ characters){nc}")
        print(f"  {yellow}[→] Ensure good character variety{nc}")
    elif supercomputer_time < 3153600000:  # Less than 100 years
        print(f"  {green}[✓] This password is reasonably secure{nc}")
        print(f"  {green}[→] Suitable for most personal accounts{nc}")
    else:
        print(f"  {bgreen}[✓] Excellent! This password is very secure{nc}")
        print(f"  {bgreen}[→] Suitable for high-security applications{nc}")
    
    print(f"\n{cyan}Note: These estimates assume simple brute force attacks.{nc}")
    print(f"{cyan}Dictionary attacks or social engineering may be faster.{nc}")
    print(f"\n{bpurple}{'='*70}{nc}\n")


def generate_syllable(pattern: str, use_clear_consonants: bool = False) -> str:
    """Generates a syllable based on a pattern (c=consonant, v=vowel)."""
    consonant_pool = CLEAR_CONSONANTS if use_clear_consonants else CONSONANTS
    syllable = ""
    for char in pattern:
        if char == 'c':
            syllable += secrets.choice(consonant_pool)
        elif char == 'v':
            syllable += secrets.choice(VOWELS)
    return syllable


def generate_pronounceable_password(length: int, add_numbers: bool = True, 
                                   add_special: bool = False, 
                                   capitalize: bool = True,
                                   use_clear_consonants: bool = False) -> str:
    """Generates a pronounceable password using phonetic patterns."""
    if length < 4:
        raise ValueError("Length must be at least 4 for pronounceable passwords.")
    
    password = ""
    
    # Reserve space for numbers and special characters if needed
    reserved_chars = 0
    if add_numbers:
        reserved_chars += secrets.randbelow(2) + 1  # 1 or 2
    if add_special:
        reserved_chars += 1
    
    base_length = length - reserved_chars
    
    # Generate pronounceable base using syllables
    while len(password) < base_length:
        pattern = secrets.choice(SYLLABLE_PATTERNS)
        syllable = generate_syllable(pattern, use_clear_consonants)
        
        # Don't exceed desired length
        if len(password) + len(syllable) <= base_length:
            password += syllable
        else:
            # Fill remaining space with simple cv pattern
            remaining = base_length - len(password)
            if remaining == 1:
                password += random.choice(VOWELS if password[-1] in CONSONANTS else CONSONANTS)
            elif remaining == 2:
                password += generate_syllable("cv", use_clear_consonants)
            else:
                password += generate_syllable("cvc", use_clear_consonants)[:remaining]
            break
    
    # Apply capitalization
    if capitalize:
        # Randomly capitalize some letters for better security
        password_list = list(password)
        num_caps = secrets.randbelow(max(2, len(password) // 3)) + 1
        cap_positions = secrets.SystemRandom().sample(range(len(password_list)), min(num_caps, len(password_list)))
        for pos in cap_positions:
            password_list[pos] = password_list[pos].upper()
        password = "".join(password_list)
    
    # Convert to list for inserting numbers and special chars
    password_list = list(password)
    
    # Add numbers at random positions
    if add_numbers:
        num_count = min(reserved_chars if not add_special else reserved_chars - 1, 2)
        for _ in range(num_count):
            digit = str(secrets.randbelow(10))
            # Insert at random position (prefer end for easier pronunciation)
            if secrets.randbelow(100) < 70:  # 70% chance to add at end
                password_list.append(digit)
            else:
                pos = secrets.randbelow(len(password_list) + 1)
                password_list.insert(pos, digit)
    
    # Add special character
    if add_special:
        special_char = secrets.choice(SPECIAL_CHARACTERS)
        # Add at end for easier pronunciation
        if secrets.randbelow(100) < 80:  # 80% chance to add at end
            password_list.append(special_char)
        else:
            pos = secrets.randbelow(len(password_list) + 1)
            password_list.insert(pos, special_char)
    
    return "".join(password_list)


def handle_pronounceable_password() -> None:
    print(f"\n{cyan}Generate a pronounceable password that's easier to remember and speak.{nc}\n")
    
    try:
        length = int(input(f"{purple}Enter the desired password length ({MIN_PASSWORD_LENGTH}-{MAX_PASSWORD_LENGTH}): {nc}"))
    except ValueError:
        print(f"{red}Please enter a valid number for the length.{nc}")
        return
    
    if not MIN_PASSWORD_LENGTH <= length <= MAX_PASSWORD_LENGTH:
        print(f"{red}Length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}.{nc}")
        return
    
    if length < 6:
        print(f"{yellow}Warning: Very short passwords may not be very secure.{nc}")
    
    add_numbers = prompt_yes_no("Add numbers for extra security")
    add_special = prompt_yes_no("Add special characters for extra security")
    capitalize = prompt_yes_no("Use random capitalization")
    use_clear = prompt_yes_no("Use only clear consonants (avoid y, q)")
    
    try:
        password = generate_pronounceable_password(length, add_numbers, add_special, capitalize, use_clear)
    except ValueError as exc:
        print(f"{red}{exc}{nc}")
        return
    
    print(f"\n{bpurple}{'='*60}{nc}")
    print(f"{green}Generated Pronounceable Password: {bgreen}{password}{nc}")
    print(f"{bpurple}{'='*60}{nc}\n")
    
    # Show pronunciation guide
    print(f"{cyan}Pronunciation Guide:{nc}")
    base_word = "".join([c for c in password if c.isalpha()])
    chunks = []
    i = 0
    while i < len(base_word):
        if i + 2 < len(base_word):
            chunks.append(base_word[i:i+3])
            i += 3
        elif i + 1 < len(base_word):
            chunks.append(base_word[i:i+2])
            i += 2
        else:
            chunks.append(base_word[i])
            i += 1
    
    print(f"{cyan}  Break it down: {purple}{'-'.join(chunks)}{nc}")
    
    # Quick strength check
    entropy = calculate_entropy(password)
    print(f"\n{cyan}Password Entropy: {entropy:.2f} bits{nc}")
    
    if entropy < 40:
        print(f"{yellow}Tip: Consider making it longer for better security.{nc}")
    else:
        print(f"{green}This password has good security!{nc}")
    
    print()


def handle_entropy_check() -> None:
    password = input(f"{purple}Enter the password to check its entropy: {nc}")
    entropy = calculate_entropy(password)
    print(f"{green}Password entropy: {entropy:.2f} bits{nc}")
    if entropy < ENTROPY_THRESHOLDS["low"]:
        print(f"{red}Entropy looks low. Consider a longer password or more varied characters.{nc}")
    elif entropy < ENTROPY_THRESHOLDS["moderate"]:
        print(f"{yellow}Entropy is moderate. Stronger is recommended for sensitive accounts.{nc}")
    else:
        print(f"{green}Entropy looks strong for most uses.{nc}")


def load_words_from_file(file_path: Path) -> List[str]:
    """Load words from file with error handling."""
    if not file_path.exists():
        print(f"{red}Word list not found: {file_path}{nc}")
        return []

    try:
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            words = [line.strip() for line in handle if line.strip()]
    except (UnicodeDecodeError, IOError) as e:
        print(f"{red}Could not read the word list: {e}{nc}")
        return []

    if not words:
        print(f"{red}The word list is empty.{nc}")
    return words


def load_words_from_file_safe(file_path: Path, min_word_length: int = 1) -> Tuple[List[str], str]:
    """Load words from file with improved error handling.
    
    Args:
        file_path: Path to the file
        min_word_length: Minimum length of a valid word
    
    Returns:
        Tuple of (word_list, status_message)
    """
    if not file_path.exists():
        return [], f"Word list file not found: {file_path}"
    
    if not file_path.is_file():
        return [], f"Path is not a file: {file_path}"
    
    try:
        file_size = file_path.stat().st_size
        if file_size == 0:
            return [], "Word list file is empty"
        
        # Safety limit: don't load files > 500MB
        if file_size > 500 * 1024 * 1024:
            return [], f"File too large ({file_size / 1024 / 1024:.1f} MB, max 500MB)"
        
        words = []
        with file_path.open("r", encoding="utf-8", errors="ignore") as handle:
            for line_num, line in enumerate(handle, 1):
                word = line.strip()
                if word and len(word) >= min_word_length:
                    words.append(word)
                # Safety limit: maximum 1 million words
                if len(words) >= 1_000_000:
                    return words, f"Limit of 1M words reached (processed {line_num} lines)"
        
        if not words:
            return [], "No valid words found in file"
        
        return words, f"Loaded {len(words):,} words from {file_path.name}"
    
    except PermissionError:
        return [], f"Permission denied for reading: {file_path}"
    except IOError as e:
        return [], f"I/O error reading file: {e}"
    except Exception as e:
        return [], f"Unexpected error loading word list: {type(e).__name__}: {e}"


def generate_passphrase(word_count: int, wordlist_path: Path = WORDLIST_FILE) -> str:
    words = load_words_from_file(wordlist_path)
    if not words:
        raise ValueError("Word list is missing or empty.")
    if word_count < MIN_PASSPHRASE_WORDS:
        raise ValueError(f"Passphrase must contain at least {MIN_PASSPHRASE_WORDS} words.")
    if word_count > len(words):
        raise ValueError("Not enough words in the list to build the passphrase.")

    return " ".join(secrets.SystemRandom().sample(words, k=word_count))



def handle_passphrase_generation() -> None:
    try:
        word_count = int(input(f"{purple}How many words should the passphrase contain? (minimum {MIN_PASSPHRASE_WORDS}): {nc}"))
    except ValueError:
        print(f"{red}Please enter a valid number for the word count.{nc}")
        return

    try:
        passphrase = generate_passphrase(word_count)
    except ValueError as exc:
        print(f"{red}{exc}{nc}")
        return

    print(f"{green}Generated passphrase: {passphrase}{nc}")
    
    # Analyze generated passphrase if zxcvbn is available
    if HAS_ZXCVBN and zxcvbn is not None:
        try:
            analysis = zxcvbn(passphrase)
            score = analysis.get('score', 0)
            guesses = analysis.get('guesses', 0)
            import math
            entropy = math.log2(guesses) if guesses > 0 else 0
            print(f"{cyan}zxcvbn analysis - Score: {score}/4, Entropy: {entropy:.1f} bits{nc}")
        except Exception:
            pass


SUBSTITUTIONS = {
    "a": ["a", "A", "4", "@"],
    "b": ["b", "B", "8"],
    "c": ["c", "C", "("],
    "d": ["d", "D"],
    "e": ["e", "E", "3"],
    "f": ["f", "F"],
    "g": ["g", "G", "9"],
    "h": ["h", "H"],
    "i": ["i", "I", "1", "!"],
    "j": ["j", "J"],
    "k": ["k", "K"],
    "l": ["l", "L", "1"],
    "m": ["m", "M"],
    "n": ["n", "N"],
    "o": ["o", "O", "0"],
    "p": ["p", "P"],
    "q": ["q", "Q"],
    "r": ["r", "R"],
    "s": ["s", "S", "5", "$"],
    "t": ["t", "T"],
    "u": ["u", "U"],
    "v": ["v", "V"],
    "w": ["w", "W"],
    "x": ["x", "X"],
    "y": ["y", "Y"],
    "z": ["z", "Z", "2"],
}


def generate_similar_passwords(password: str, max_results: int = MAX_SIMILAR_RESULTS, seed: Optional[int] = None):
    """Generate variants with a cap to avoid combinatorial explosion; deterministic if seed provided.
    
    Note: Uses cryptographically secure random by default. Only uses random.Random if seed is provided
    for deterministic/reproducible results (not recommended for security-critical operations).
    """
    if len(password) > 32:
        raise ValueError("Password too long for variant generation (max 32 chars)")

    # Use deterministic random only if seed is explicitly provided
    rng = random.Random(seed) if seed is not None else secrets.SystemRandom()

    # Estimate total combinations
    total_variants = 1
    for ch in password:
        total_variants *= len(SUBSTITUTIONS.get(ch.lower(), [ch]))

    # If explosion risk, sample randomly up to max_results with dedup
    if total_variants > max_results:
        sampled = set()
        while len(sampled) < max_results:
            variant = "".join(rng.choice(SUBSTITUTIONS.get(ch.lower(), [ch])) for ch in password)
            sampled.add(variant)
        return list(sampled)

    results = []

    def backtrack(index: int, current: str) -> None:
        if len(results) >= max_results:
            return
        if index == len(password):
            results.append(current)
            return

        ch = password[index]
        variants = SUBSTITUTIONS.get(ch.lower(), [ch])
        seen = set()
        for variant in variants:
            if variant in seen:
                continue
            seen.add(variant)
            backtrack(index + 1, current + variant)

    backtrack(0, "")
    return results


def handle_similar_passwords() -> None:
    password = input(f"{purple}Enter the password to generate similar variations: {nc}")
    seed = input(f"{purple}Optional seed for deterministic sampling (empty = random): {nc}").strip()
    seed_val = int(seed) if seed else None
    try:
        variants = generate_similar_passwords(password, seed=seed_val)
    except ValueError as exc:
        print_error(str(exc))
        return
    print(f"{green}Generated {len(variants)} similar passwords (capped at {MAX_SIMILAR_RESULTS} to avoid explosion):{nc}")
    for idx, variant in enumerate(variants, 1):
        print(f"{idx}. {variant}")


# ============================================================================
# ADVANCED ANALYSIS FUNCTIONS
# ============================================================================

def detect_common_patterns(password: str) -> list:
    """Detects common patterns in password like dates, sequences, common names."""
    patterns_found = []
    password_lower = password.lower()
    
    # Check for common date patterns (YYYY, MMDD, DDMM, etc.)
    date_patterns = []
    
    # Year patterns (1900-2099)
    for year in range(1900, 2100):
        if str(year) in password:
            date_patterns.append(f"Year: {year}")
    
    # Common date formats (MM/DD, DD/MM, etc.)
    date_regex = [
        # MMDD and DDMM without word boundaries
        (r'(0[1-9]|1[0-2])([0-2]\d|3[01])', 'Date pattern MMDD'),
        (r'([0-2]\d|3[01])(0[1-9]|1[0-2])', 'Date pattern DDMM'),
        # 8-digit formats without separators
        (r'(19|20)\d{2}(0[1-9]|1[0-2])([0-2]\d|3[01])', 'Date pattern YYYYMMDD'),
        (r'(0[1-9]|1[0-2])([0-2]\d|3[01])(19|20)\d{2}', 'Date pattern MMDDYYYY'),
        (r'([0-2]\d|3[01])(0[1-9]|1[0-2])(19|20)\d{2}', 'Date pattern DDMMYYYY'),
    ]
    
    for regex, desc in date_regex:
        if re.search(regex, password):
            date_patterns.append(desc)
    
    if date_patterns:
        patterns_found.append({
            "category": "Date Patterns",
            "items": date_patterns,
            "risk": "High - Easy to guess if tied to personal dates"
        })
    
    # Check for numeric sequences (123, 456, 789, 000, 111, etc.)
    sequence_patterns = []
    for i in range(10):
        seq = str(i) * 3
        if seq in password:
            sequence_patterns.append(f"Repetition: '{seq}'")
    
    # Ascending/descending sequences
    for i in range(8):
        asc_seq = "".join(str((i + j) % 10) for j in range(3))
        if asc_seq in password:
            sequence_patterns.append(f"Sequence: '{asc_seq}'")
    
    if sequence_patterns:
        patterns_found.append({
            "category": "Numeric Sequences",
            "items": sequence_patterns,
            "risk": "Medium - Pattern-based guessing possible"
        })
    
    # Check for common names and words
    common_names = [
        "john", "jane", "john123", "admin", "user", "root", "test",
        "password", "pass", "secret", "hello", "world", "qwerty"
    ]
    
    name_patterns = []
    for name in common_names:
        if name in password_lower:
            name_patterns.append(f"Common word: '{name}'")
    
    if name_patterns:
        patterns_found.append({
            "category": "Common Words/Names",
            "items": name_patterns,
            "risk": "High - Dictionary attacks likely to succeed"
        })
    
    # Check for keyboard walks (adjacent keys on keyboard)
    keyboard_patterns = {
        "qwerty": "Horizontal walk",
        "qwertyuiop": "Full row walk",
        "asdfgh": "Horizontal walk",
        "zxcvbn": "Horizontal walk",
        "1234": "Number row walk",
        "qazwsx": "Zigzag walk",
        "qweasd": "Zigzag walk"
    }
    
    keyboard_found = []
    for pattern, desc in keyboard_patterns.items():
        if pattern in password_lower:
            keyboard_found.append(f"{desc}: '{pattern}'")
    
    if keyboard_found:
        patterns_found.append({
            "category": "Keyboard Patterns",
            "items": keyboard_found,
            "risk": "High - Keyboard walk attacks can crack these"
        })
    
    # Check for character repetition
    repeat_patterns = []
    max_repeat = 1
    current_repeat = 1
    for i in range(1, len(password)):
        if password[i] == password[i-1]:
            current_repeat += 1
            max_repeat = max(max_repeat, current_repeat)
        else:
            current_repeat = 1
    
    if max_repeat >= 3:
        repeat_patterns.append(f"Character repeated {max_repeat} times")
        patterns_found.append({
            "category": "Character Repetition",
            "items": repeat_patterns,
            "risk": "Medium - Reduces effective password space"
        })
    
    return patterns_found


def get_character_statistics(password: str) -> dict:
    """Analyzes character distribution in password."""
    stats = {
        "lowercase": 0,
        "uppercase": 0,
        "digits": 0,
        "special": 0,
        "other": 0,
        "total": len(password),
    }
    
    char_breakdown = {}
    
    for ch in password:
        char_breakdown[ch] = char_breakdown.get(ch, 0) + 1
        
        if ch.islower():
            stats["lowercase"] += 1
        elif ch.isupper():
            stats["uppercase"] += 1
        elif ch.isdigit():
            stats["digits"] += 1
        elif ch in SPECIAL_CHARACTERS:
            stats["special"] += 1
        else:
            stats["other"] += 1
    
    # Sort characters by frequency
    sorted_chars = sorted(char_breakdown.items(), key=lambda x: x[1], reverse=True)
    
    return {
        "stats": stats,
        "distribution": sorted_chars,
        "entropy": calculate_entropy(password),
    }


def handle_pattern_detection() -> None:
    """Interactive pattern detection for passwords."""
    password = input(f"{purple}Enter the password to analyze for patterns: {nc}")
    
    if not password:
        print(f"{red}Password cannot be empty.{nc}")
        return
    
    patterns = detect_common_patterns(password)
    
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}PATTERN DETECTION ANALYSIS{nc}")
    print(f"{bpurple}{'='*70}{nc}\n")
    
    if not patterns:
        print(f"{green}✓ No common patterns detected! Your password is more secure.{nc}\n")
    else:
        print(f"{red}⚠ Common patterns found:{nc}\n")
        
        for pattern_group in patterns:
            risk_color = red if "High" in pattern_group["risk"] else yellow
            print(f"{bpurple}├─ {pattern_group['category']}{nc}")
            for item in pattern_group['items']:
                print(f"{purple}│  ├─ {item}{nc}")
            print(f"{purple}│  └─ {risk_color}Risk: {pattern_group['risk']}{nc}\n")
    
    print(f"{yellow}Recommendation:{nc}")
    print(f"{yellow}  Use random combinations without recognizable patterns{nc}")
    print(f"{yellow}  Avoid dates, names, keyboard walks, and sequences{nc}")
    print(f"\n{bpurple}{'='*70}{nc}\n")


def handle_character_statistics() -> None:
    """Interactive character distribution analysis."""
    password = input(f"{bpurple}Enter the password to analyze: {nc}")
    
    if not password:
        print(f"{red}Password cannot be empty.{nc}")
        return
    
    analysis = get_character_statistics(password)
    stats = analysis["stats"]
    distribution = analysis["distribution"]
    entropy = analysis["entropy"]
    
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}CHARACTER STATISTICS{nc}")
    print(f"{bpurple}{'='*70}{nc}\n")
    
    # Character type breakdown
    print(f"{purple}Character Type Breakdown:{nc}")
    print(f"  Lowercase letters:  {stats['lowercase']:3d} chars {purple}({stats['lowercase']*100//stats['total']:3d}%){nc}", end="")
    print(f"  {'█' * (stats['lowercase'] * 30 // stats['total'])}")
    
    print(f"  Uppercase letters:  {stats['uppercase']:3d} chars {purple}({stats['uppercase']*100//stats['total']:3d}%){nc}", end="")
    print(f"  {'█' * (stats['uppercase'] * 30 // stats['total'])}")
    
    print(f"  Digits:             {stats['digits']:3d} chars {purple}({stats['digits']*100//stats['total']:3d}%){nc}", end="")
    print(f"  {'█' * (stats['digits'] * 30 // stats['total'])}")
    
    print(f"  Special chars:      {stats['special']:3d} chars {purple}({stats['special']*100//stats['total']:3d}%){nc}", end="")
    print(f"  {'█' * (stats['special'] * 30 // stats['total'])}")
    
    print(f"  Other chars:        {stats['other']:3d} chars {purple}({stats['other']*100//stats['total']:3d}%){nc}", end="")
    print(f"  {'█' * (stats['other'] * 30 // stats['total'])}\n")
    
    # Most frequent characters
    print(f"{bpurple}Most Frequent Characters:{nc}")
    for char, count in distribution[:5]:
        freq = count * 100 // stats['total']
        display_char = char if char != ' ' else '(space)'
        print(f"  {purple}'{display_char}'{nc}: {count} times ({freq}%)")
    
    # Entropy
    print(f"\n{bpurple}Entropy Analysis:{nc}")
    print(f"  Total Entropy: {purple}{entropy:.2f} bits{nc}")
    
    if entropy < 40:
        print(f"  Assessment: {red}Low entropy - password may be weak{nc}")
    elif entropy < 60:
        print(f"  Assessment: {yellow}Moderate entropy - acceptable but improvable{nc}")
    else:
        print(f"  Assessment: {green}High entropy - good randomness{nc}")
    
    print(f"\n{bpurple}{'='*70}{nc}\n")


def handle_password_audit() -> None:
    """Audit multiple passwords for security analysis."""
    print(f"\n{purple}Password Audit Tool - Test multiple passwords{nc}\n")
    
    source = input(f"{bpurple}Load from (f)ile or (m)anual input? [f/m]: {nc}").strip().lower()
    
    passwords = []
    
    if source == 'f':
        file_path = input(f"{bpurple}Enter the file path: {nc}").strip()
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                passwords = [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            print(f"{red}File not found.{nc}")
            return
        except Exception as e:
            print(f"{red}Error reading file: {e}{nc}")
            return
    else:
        print(f"{purple}Enter passwords (one per line, empty line to finish):{nc}")
        while True:
            pwd = input(f"{bpurple}> {nc}").strip()
            if not pwd:
                break
            passwords.append(pwd)
    
    if not passwords:
        print(f"{red}No passwords to audit.{nc}")
        return
    
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}PASSWORD AUDIT REPORT{nc}")
    print(f"{bpurple}{'='*70}{nc}")
    print(f"{purple}Total passwords analyzed: {len(passwords)}{nc}\n")
    
    results = []
    for idx, pwd in enumerate(passwords, 1):
        analysis = analyze_password_strength(pwd)
        
        results.append({
            "index": idx,
            "password": pwd if len(pwd) <= 20 else pwd[:17] + "...",
            "score": analysis["score"],
            "level": analysis["level"],
            "color": analysis["color"],
        })
    
    # Sort by score
    results.sort(key=lambda x: x["score"])
    
    # Display detailed results
    for result in results:
        color = result["color"]
        print(f"{purple}[{result['index']:2d}] {color}{result['level']:12s} (Score: {result['score']:3d}/100){nc} | {result['password']}")
    
    # Summary statistics
    scores = [r["score"] for r in results]
    avg_score = sum(scores) / len(scores) if scores else 0
    
    print(f"\n{purple}Summary Statistics:{nc}")
    print(f"  Minimum Score: {min(scores) if scores else 0}/100")
    print(f"  Maximum Score: {max(scores) if scores else 0}/100")
    print(f"  Average Score: {avg_score:.1f}/100")
    print(f"  Median Score:  {sorted(scores)[len(scores)//2] if scores else 0}/100")
    
    # Count by level
    level_counts = {}
    for result in results:
        level = result["level"]
        level_counts[level] = level_counts.get(level, 0) + 1
    
    print(f"\n{purple}Distribution by Strength Level:{nc}")
    for level, count in sorted(level_counts.items()):
        print(f"  {level}: {count} password(s)")
    
    print(f"\n{bpurple}{'='*70}{nc}\n")


def handle_build_breach_index() -> None:
    """Build Bloom filter index for fast lookups."""
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}BUILD BREACH INDEX - BLOOM FILTER{nc}")
    print(f"{bpurple}{'='*70}{nc}\n")
    
    # Allow configuration via either size/k or target false positive rate
    mode = input(f"{bpurple}Configure by (s)ize or (p)robability (default p=0.01): {nc}").strip().lower() or "p"
    if mode == "s":
        try:
            size_bits = int(input(f"{purple}Bloom size (bits, default 256000000): {nc}") or 256_000_000)
            hash_count = int(input(f"{bpurple}Hash functions k (default 7): {nc}") or 7)
        except ValueError:
            print_warning("Invalid parameters. Using defaults.")
            size_bits, hash_count = 256_000_000, 7
    else:
        # Compute m and k from desired false positive rate after counting entries
        try:
            target_p = float(input(f"{bpurple}Target false positive rate p (default 0.01): {nc}") or 0.01)
        except ValueError:
            target_p = 0.01
        # Count entries
        n = 0
        try:
            with BREACH_FILE.open("r", encoding="utf-8", errors="ignore") as h:
                for _ in h:
                    n += 1
        except Exception as e:
            print_error(f"Error counting entries: {e}")
            return
        ln2_sq = (math.log(2) ** 2)
        m = int(- (n * math.log(target_p)) / ln2_sq)
        k = max(1, int((m / n) * math.log(2)))
        size_bits, hash_count = m, k
        print(f"{cyan}Computed Bloom params:{nc} size_bits={m:,}, k={k}, entries={n:,}")
        # Show estimated p given rounding
        p_est = (1 - math.exp(-(k * n) / m)) ** k if m > 0 else 1.0
        print(f"{cyan}Estimated false positive p≈{p_est:.6f}{nc}")
    
    ok, msg = build_bloom_filter(BREACH_FILE, BLOOM_FILE, size_bits=size_bits, hash_count=hash_count)
    if ok:
        print_success(msg)
    else:
        print_error(msg)
    print()


ACCOUNT_TYPES = {
    "email": {
        "name": "Email Account",
        "requirements": [
            "At least 12-16 characters (longer is better for critical accounts)",
            "Mix of uppercase, lowercase, numbers, and special characters",
            "No personal information (birthdate, name, etc.)",
            "Consider using a passphrase for easier memorization",
            "Enable two-factor authentication on the email provider",
        ],
        "avoid": [
            "Names or usernames",
            "Birth dates or anniversaries",
            "Sequential characters or patterns",
            "Dictionary words without modification",
        ],
        "suggestions": [
            "Use a password manager to generate and store",
            "Update every 6-12 months",
            "Use unique passwords for recovery and main account",
        ]
    },
    "banking": {
        "name": "Banking/Financial Account",
        "requirements": [
            "Minimum 16+ characters (very strong protection required)",
            "Mandatory uppercase, lowercase, numbers AND special characters",
            "Absolutely no personal identifiable information",
            "Random combination without any recognizable patterns",
            "Consider a passphrase approach for very strong protection",
        ],
        "avoid": [
            "Phone number or address components",
            "Account numbers or card details",
            "Easy-to-type sequences",
            "Common words or names",
            "Reusing passwords from other accounts",
        ],
        "suggestions": [
            "Store only in a secure password manager",
            "Change quarterly or semi-annually",
            "Never enter on unsecured networks",
            "Enable all available security features (2FA, SMS alerts)",
        ]
    },
    "social": {
        "name": "Social Media Account",
        "requirements": [
            "Minimum 10-12 characters",
            "Mix of character types (uppercase, lowercase, numbers)",
            "No usernames or profile names in the password",
            "Avoid personal references",
        ],
        "avoid": [
            "Your username or handle",
            "Friends' or family members' names",
            "Famous quotes or song lyrics",
            "Information visible in your profile",
        ],
        "suggestions": [
            "Different from email and banking passwords",
            "Enable two-factor authentication",
            "Check login history regularly",
            "Update every 6 months",
        ]
    },
    "work": {
        "name": "Work/Corporate Account",
        "requirements": [
            "Follow company policy (usually 12+ characters)",
            "Mix of uppercase, lowercase, numbers, special characters",
            "No company/employee information",
            "No publicly available personal information",
            "Complex enough to resist dictionary attacks",
        ],
        "avoid": [
            "Department or project names",
            "Office location or address",
            "Employee ID or extension",
            "Company name abbreviations",
            "Passwords from personal accounts",
        ],
        "suggestions": [
            "Keep separate from personal passwords",
            "Use a password manager (if company allows)",
            "Comply with company password policies",
            "Change when leaving the company",
            "Never share with colleagues",
        ]
    },
    "gaming": {
        "name": "Gaming Account",
        "requirements": [
            "8-12 characters minimum",
            "Mix of uppercase, lowercase, numbers, special characters",
            "No gaming-related terms or references",
            "No usernames or character names",
        ],
        "avoid": [
            "Your gaming username or handle",
            "Favorite game titles or characters",
            "Guild or clan names",
            "Friend usernames",
        ],
        "suggestions": [
            "Different from banking/work passwords",
            "Enable 2FA if available",
            "Protect email account linked to gaming account",
            "Update every 6-12 months",
        ]
    },
    "other": {
        "name": "General Account",
        "requirements": [
            "Minimum 8-10 characters",
            "Mix of uppercase, lowercase, numbers, special characters",
            "Random and unpredictable",
            "Not based on personal information",
        ],
        "avoid": [
            "Personal names or usernames",
            "Sequential or repetitive patterns",
            "Common words from dictionaries",
            "Reusing passwords from other accounts",
        ],
        "suggestions": [
            "Use unique passwords for each account",
            "Enable two-factor authentication where available",
            "Store in a password manager",
            "Update periodically",
        ]
    }
}


def handle_custom_recommendations() -> None:
    """Provide custom password recommendations based on account type."""
    print(f"\n{bpurple}Select Account Type:{nc}\n")
    
    account_types_list = list(ACCOUNT_TYPES.keys())
    for idx, acc_type in enumerate(account_types_list, 1):
        color = bpurple if idx % 2 == 1 else purple
        print(f"{color}[{idx}] {ACCOUNT_TYPES[acc_type]['name']}{nc}")
    
    try:
        choice = int(input(f"\n{bpurple}Select option (1-{len(account_types_list)}): {nc}"))
        if choice < 1 or choice > len(account_types_list):
            print(f"{red}Invalid selection.{nc}")
            return
        
        selected_type = account_types_list[choice - 1]
    except ValueError:
        print(f"{red}Please enter a valid number.{nc}")
        return
    
    # Optional: analyze current password
    analyze_current = prompt_yes_no("\nAnalyze an existing password for this account type?")
    
    pwd_to_analyze = None
    analysis = None
    
    if analyze_current:
        pwd_to_analyze = input(f"{purple}Enter the password to analyze: {nc}")
        if pwd_to_analyze:
            analysis = analyze_password_strength(pwd_to_analyze)
        else:
            pwd_to_analyze = None
    
    # Display recommendations
    account = ACCOUNT_TYPES[selected_type]
    
    print(f"\n{bpurple}{'='*70}{nc}")
    print(f"{bpurple}{account['name'].upper()} - CUSTOM RECOMMENDATIONS{nc}")
    print(f"{bpurple}{'='*70}{nc}\n")
    
    # Current password analysis if provided
    if analysis and pwd_to_analyze:
        color = analysis['color']
        print(f"{cyan}Current Password Analysis:{nc}")
        print(f"  Strength: {color}{analysis['level']} (Score: {analysis['score']}/100){nc}")
        print(f"  Length: {analysis['length']} characters")
        print(f"  Entropy: {calculate_entropy(pwd_to_analyze):.2f} bits\n")
    
    # Requirements
    print(f"{bpurple}Password Requirements:{nc}")
    for i, req in enumerate(account['requirements'], 1):
        print(f"  {cyan}[{i}]{nc} {req}")
    
    # What to avoid
    print(f"\n{red}What to Avoid:{nc}")
    for i, avoid in enumerate(account['avoid'], 1):
        print(f"  {red}[✗]{nc} {avoid}")
    
    # Additional suggestions
    print(f"\n{yellow}Additional Suggestions:{nc}")
    for i, suggestion in enumerate(account['suggestions'], 1):
        print(f"  {yellow}[{i}]{nc} {suggestion}")
    
    # Suggested criteria visualization
    print(f"\n{cyan}Recommended Password Criteria:{nc}")
    print(f"  {purple}├─ Length: ", end="")
    if selected_type in ["banking"]:
        print(f"{bgreen}16+ characters (CRITICAL){nc}")
    elif selected_type in ["email", "work"]:
        print(f"{green}12-16 characters{nc}")
    else:
        print(f"{green}10-12 characters{nc}")
    
    print(f"  {purple}├─ Uppercase: {green}Yes{nc}")
    print(f"  {purple}├─ Lowercase: {green}Yes{nc}")
    print(f"  {purple}├─ Numbers: {green}Yes{nc}")
    
    if selected_type in ["banking", "work"]:
        print(f"  {purple}└─ Special Chars: {bgreen}REQUIRED{nc}")
    else:
        print(f"  {purple}└─ Special Chars: {green}Recommended{nc}")
    
    print(f"\n{bpurple}{'='*70}{nc}\n")


def exit_animation() -> None:
    """Display an animated exit sequence with color effects."""
    print()
    
    # Closing sequence animation
    colors = [bpurple, purple, red, bred, white]
    
    # Top border closing
    print(f"\n{bpurple}{'╔' + '═'*68 + '╗'}{nc}")
    
    for i in range(3):
        time.sleep(0.15)
        spaces = ' ' * (34 - i)
        print(f"\r{bpurple}║{spaces}{colors[i % len(colors)]}Closing{' ' * i}...{nc}{bpurple}{'.' * i}  ║{nc}", end='', flush=True)
    
    print()
    time.sleep(0.2)
    
    # Goodbye message with color wave
    goodbye_text = "THANK YOU FOR USING SHIELD PASS"
    print(f"{bpurple}║{nc}", end='')
    
    for idx, char in enumerate(goodbye_text):
        color = colors[idx % len(colors)]
        print(f"{color}{char}{nc}", end='', flush=True)
        time.sleep(0.02)
    
    spaces_after = 68 - len(goodbye_text)
    print(f"{bpurple}{'─' * spaces_after}║{nc}")
    
    time.sleep(0.2)
    
    # Countdown
    print(f"{bpurple}║{nc} ", end='')
    countdown_msg = "See you next time..."
    for char in countdown_msg:
        print(f"{purple}{char}{nc}", end='', flush=True)
        time.sleep(0.03)
    
    spaces_countdown = 68 - len(countdown_msg) - 1
    print(f"{bpurple}{'─' * spaces_countdown}║{nc}")
    
    time.sleep(0.3)
    
    # Bottom border closing
    print(f"{bpurple}{'╚' + '═'*68 + '╝'}{nc}")
    
    time.sleep(0.2)
    
    # Color fade out effect
    fade_colors = [bpurple, purple, red, bred]
    for color in fade_colors:
        print(f"{color}{'▓' * 70}{nc}")
        time.sleep(0.1)
    
    print(f"{purple}{'░' * 70}{nc}")
    time.sleep(0.1)
    
    # Final message
    print(f"\n{bpurple}Exiting...{nc}\n")
    time.sleep(0.3)




# ============================================================================
# UTILITY FUNCTIONS
# ============================================================================

def safe_input(prompt: str, input_type: type = str, default=None):
    """Safe input with type conversion and default value.
    
    Args:
        prompt: The prompt to display
        input_type: Expected type (int, str, float)
        default: Default value if user enters nothing
        
    Returns:
        Converted input or default value
    """
    while True:
        try:
            user_input = input(prompt).strip()
            if not user_input and default is not None:
                return default
            if not user_input:
                continue
            return input_type(user_input)
        except ValueError:
            print(f"{red}Invalid input. Please enter a valid {input_type.__name__}.{nc}")


def print_section_header(title: str, width: int = 70) -> None:
    """Print a formatted section header."""
    print(f"\n{bpurple}{'='*width}{nc}")
    padding = (width - len(title)) // 2
    print(f"{bpurple}{' '*padding}{title}{nc}")
    print(f"{bpurple}{'='*width}{nc}\n")


def print_subsection(title: str) -> None:
    """Print a formatted subsection header."""
    print(f"\n{bpurple}├─ {title}{nc}")


def print_success(message: str) -> None:
    """Print a success message."""
    print(f"{green}✓ {message}{nc}")


def print_error(message: str) -> None:
    """Print an error message."""
    print(f"{red}✗ {message}{nc}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    print(f"{yellow}⚠ {message}{nc}")


def main_menu() -> None:
    print(logo)
    while True:
        print(
            f"""
{red}[*] Select an option:{nc}
{bpurple}[1] Generate Random Password{nc}
{purple}[2] Check Password Against Breach List{nc}
{bpurple}[3] Check Password Entropy{nc}
{purple}[4] Analyze Password Strength{nc}
{bpurple}[5] Brute Force Crack Time Test{nc}
{purple}[6] Generate Passphrase{nc}
{bpurple}[7] Generate Pronounceable Password{nc}
{purple}[8] Generate Similar Passwords{nc}

{red}--- ADVANCED ANALYSIS ---{nc}
{bpurple}[9] Pattern Detection{nc}
{purple}[10] Character Statistics{nc}
{bpurple}[11] Password Audit (Multiple Passwords){nc}
{purple}[12] Custom Recommendations by Account Type{nc}
{bpurple}[13] Build Breach Index (Bloom){nc}

{purple}[14] Exit{nc}
"""
        )

        choice = input(f"{byellow}Enter your choice: {nc}").strip()

        try:
            if choice == "1":
                handle_generate_password()
            elif choice == "2":
                password = input(f"{purple}Enter the password to check: {nc}")
                if password:
                    breached, message = check_password_breach(password)
                    print(f"{green if not breached else red}{message}{nc}\n")
                else:
                    print_error("Password cannot be empty")
            elif choice == "3":
                handle_entropy_check()
            elif choice == "4":
                handle_password_strength_analysis()
            elif choice == "5":
                handle_crack_time_test()
            elif choice == "6":
                handle_passphrase_generation()
            elif choice == "7":
                handle_pronounceable_password()
            elif choice == "8":
                handle_similar_passwords()
            elif choice == "9":
                handle_pattern_detection()
            elif choice == "10":
                handle_character_statistics()
            elif choice == "11":
                handle_password_audit()
            elif choice == "12":
                handle_custom_recommendations()
            elif choice == "13":
                handle_build_breach_index()
            elif choice == "14":
                exit_animation()
                break
            else:
                print_error("Invalid choice, please try again")
        except KeyboardInterrupt:
            print(f"\n{yellow}Operation cancelled by user.{nc}\n")
        except Exception as e:
            print_error(f"An unexpected error occurred: {e}")


if __name__ == "__main__":
    main_menu()