import re

# Cryptographic signature database based on industry-standard regex patterns
HASH_DICTIONARY = {
    "MD5": {
        "regex": r"^[0-9a-fA-F]{32}$",
        "info": "Legacy algorithm (32 hexadecimal characters). Very common, vulnerable to collisions."
    },
    "SHA-1": {
        "regex": r"^[0-9a-fA-F]{40}$",
        "info": "Deprecated standard (40 hexadecimal characters). Used in older systems and Git."
    },
    "SHA-256": {
        "regex": r"^[0-9a-fA-F]{64}$",
        "info": "Current secure standard (64 hexadecimal characters). Used in web protocols and Blockchain."
    },
    "SHA-512": {
        "regex": r"^[0-9a-fA-F]{128}$",
        "info": "High-security algorithm from the SHA-2 family (128 hexadecimal characters)."
    },
    "NTLM / LM (Windows)": {
        "regex": r"^[0-9a-fA-F]{32}$",
        "info": "Microsoft Windows local/domain authentication hash (SAM database and Active Directory)."
    },
    "MySQL 4.1+": {
        "regex": r"^\*[0-9a-fA-F]{40}$",
        "info": "Hashing format used by MySQL and MariaDB database servers (starts with *)."
    },
    "bcrypt": {
        "regex": r"^\$2[axy]\$[0-9]{2}\$[./A-Za-z0-9]{53}$",
        "info": "Secure Blowfish-based algorithm with adaptive salt (Linux standard and modern web frameworks)."
    },
    "md5(wordpress) / phpass": {
        "regex": r"^\$P\$[./A-Za-z0-9]{31}$",
        "info": "Specific format used by WordPress CMS to protect passwords in the database."
    },
    "Cisco Type 7": {
        "regex": r"^[0-9]{2}[0-9a-fA-F]+$",
        "info": "Weak encryption used in Cisco router configuration files (easily reversible)."
    }
}

def analyze_hash(hash_string):
    hash_string = hash_string.strip()
    matches_found = []
    
    for algorithm_name, rules in HASH_DICTIONARY.items():
        if re.match(rules["regex"], hash_string):
            matches_found.append((algorithm_name, rules["info"]))
            
    return matches_found

def main():
    print("=" * 75)
    print("      🔏 PURE HASH IDENTIFIER - HIGH-SPEED CRYPTOGRAPHIC ENGINE      ")
    print("=" * 75)
    
    user_hash = input("\n[?] Enter the hash to identify: ").strip()
    
    if not user_hash:
        print("[-] Empty input. Exiting.")
        return
        
    results = analyze_hash(user_hash)
    
    if results:
        print(f"\n[*] Structural analysis completed. Detected {len(results)} possible candidate(s):\n")
        for algorithm, description in results:
            print(f" 🎯 [TYPE]: \033[1;36m{algorithm}\033[0m")
            print(f"    └── ℹ️ Details: {description}\n")
    else:
        print("\n[-] No matching algorithm found in the signature database.")
        
    print("=" * 75)

if __name__ == "__main__":
    main()
