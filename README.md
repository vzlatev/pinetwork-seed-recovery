# This tool brute-forces missing words from a **BIP39 mnemonic phrase** for **Pi Network** wallets.


## 🚀 Overview
Can help with BIP39 seed phrase recovery if you have partial information and wallet address for PI Network account. 
Mainly helpful when you’ve lost or forgotten part of your mnemonic seed phrase.



## 🛠️ Setup

### 1️⃣ Install Dependencies
Ensure you have Python 3.8+ installed. Then, run:
```bash
pip install mnemonic bip-utils stellar-sdk pynacl
```

### 2️⃣ Configure `config.json`
- Add your **known words** (as many as possible, up to 23).
- Enter the **wallet address** you're trying to recover.
- (Optional) Modify **derivation path** if needed.

Example `config.json`:
```json
{
    "known_words": ["word1", "word2", ..., "word22"],
    "target_wallet": "GXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
    "derivation_path": "m/44'/314159'/0'",
    "log_file": "recovery.log"
}
```

### 3️⃣ Run the Script
```bash
python seed_recovery.py
```

### 4️⃣ View Logs
After the script runs, check `recovery.log` for results:
```bash
cat recovery.log
```

## ✅ Compatibility
This script works on:
- **Linux** (Ubuntu, Debian, Fedora, Arch, etc.)
- **macOS** (Intel & M1/M2 chips)
- **Windows** (via WSL or Python directly)

## ⚠️ Disclaimer
**This tool is for educational purposes only. Do not use for unauthorized access.**
