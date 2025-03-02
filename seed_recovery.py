import time
import sys
import os
import json
import hashlib
from itertools import product
from mnemonic import Mnemonic
from bip_utils import Bip39MnemonicDecoder, Bip39SeedGenerator, Bip39Languages, Bip39MnemonicValidator, Bip32Slip10Ed25519
from stellar_sdk import Keypair, StrKey
import nacl.signing

# Load configuration
CONFIG_FILE = "config.json"
if not os.path.exists(CONFIG_FILE):
    raise FileNotFoundError(f"Configuration file '{CONFIG_FILE}' not found!")

with open(CONFIG_FILE, "r") as f:
    config = json.load(f)

KNOWN_WORDS = config["known_words"]
TARGET_WALLET_ADDRESS = config["target_wallet"]
DERIVATION_PATH = config.get("derivation_path", "m/44'/314159'/0'")
LOG_FILE = config.get("log_file", "recovery.log")

if len(KNOWN_WORDS) >= 24:
    raise ValueError("Known words count must be less than 24.")

# ✅ Linux Compatibility Fix: Only reconfigure stdout if supported
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

mnemo = Mnemonic("english")
wordlist = mnemo.wordlist
mnemonic_validator = Bip39MnemonicValidator(Bip39Languages.ENGLISH)

start_time = time.time()
total_checked = 0
missing_word_count = 24 - len(KNOWN_WORDS)

def log(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")
    print(message)

def find_valid_missing_words():
    valid_combinations = []
    for words in product(wordlist, repeat=missing_word_count):
        candidate_mnemonic = " ".join(KNOWN_WORDS + list(words))
        try:
            mnemonic_validator.Validate(candidate_mnemonic)
            valid_combinations.append(words)
        except:
            pass
    return valid_combinations

def derive_pi_wallet(seed_phrase):
    seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
    bip32_ctx = Bip32Slip10Ed25519.FromSeed(seed_bytes)
    derived_private_key = bip32_ctx.DerivePath(DERIVATION_PATH).PrivateKey().Raw().ToBytes()
    signing_key = nacl.signing.SigningKey(derived_private_key)
    verify_key = signing_key.verify_key
    return StrKey.encode_ed25519_public_key(bytes(verify_key))

def check_seed(missing_words):
    global total_checked
    full_seed_phrase = " ".join(KNOWN_WORDS + list(missing_words))
    derived_address = derive_pi_wallet(full_seed_phrase)
    total_checked += 1
    elapsed_time = time.time() - start_time
    words_per_sec = total_checked / elapsed_time if elapsed_time > 0 else 0
    remaining_time = (len(valid_missing_word_combinations) - total_checked) / words_per_sec if words_per_sec > 0 else float("inf")
    print(f"\r🔄 Checked: {total_checked}/{len(valid_missing_word_combinations)} | Time: {elapsed_time:.2f}s | ETA: {remaining_time:.2f}s", end='', flush=True)
    if derived_address == TARGET_WALLET_ADDRESS:
        log(f"\n🔥 Successfully Recovered Seed Phrase: {full_seed_phrase}")
        return full_seed_phrase
    return None

def recover_seed():
    for missing_words in valid_missing_word_combinations:
        result = check_seed(missing_words)
        if result:
            return result

if __name__ == "__main__":
    log(f"🚀 Finding valid missing words (checksum verified)...")
    valid_missing_word_combinations = find_valid_missing_words()
    log(f"✅ Found {len(valid_missing_word_combinations)} valid combinations. Starting brute-force...")
    recovered_seed = recover_seed()
    if recovered_seed:
        log(f"\n🔥 Successfully Recovered Seed Phrase: {recovered_seed}")
    else:
        log("\n❌ No match found. Try checking the first known words or using a different derivation path.")
