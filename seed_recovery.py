import time
import sys
import os
import json
import multiprocessing
import signal
import logging
import psutil
from itertools import islice, product
from mnemonic import Mnemonic
from bip_utils import Bip39SeedGenerator, Bip39EntropyGenerator, Bip32Slip10Ed25519
from stellar_sdk import StrKey
import nacl.signing

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("recovery.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global configuration variables
KNOWN_WORDS = []
TARGET_WALLET_ADDRESS = ""
DERIVATION_PATH = ""
DEBUG_MODE = False
BATCH_SIZE = 10000
CHUNK_SIZE = 100
MISSING_POSITIONS = []
MISSING_COUNT = 0
wordlist = []


def init_worker(fs, tc, si, vm, cl):
    """Initialize worker with shared variables"""
    global found_seed, total_checked, skipped_invalid, valid_mnemonics, counter_lock
    found_seed = fs
    total_checked = tc
    skipped_invalid = si
    valid_mnemonics = vm
    counter_lock = cl

    # Silence logging in worker processes to prevent duplication
    logging.getLogger().setLevel(logging.WARNING)


def initialize_globals():
    """Initialize global variables and configuration"""
    global KNOWN_WORDS, TARGET_WALLET_ADDRESS, DERIVATION_PATH, DEBUG_MODE
    global BATCH_SIZE, CHUNK_SIZE, MISSING_POSITIONS, MISSING_COUNT, wordlist

    # Fix multiprocessing issues on macOS - this is critical
    if sys.platform == "darwin":
        multiprocessing.set_start_method("fork", force=True)

    # Load configuration
    try:
        with open("config.json", "r") as f:
            config = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError) as e:
        logger.error(f"Error loading configuration: {e}")
        sys.exit(1)

    # Configuration variables
    KNOWN_WORDS = config["known_words"]
    TARGET_WALLET_ADDRESS = config["target_wallet"]
    DERIVATION_PATH = config.get("derivation_path", "m/44'/314159'/0'")
    DEBUG_MODE = config.get("debug_mode", False)
    BATCH_SIZE = config.get("batch_size", 5000)  # Reduced for better progress updates
    CHUNK_SIZE = config.get("chunk_size", 50)  # Reduced for better distribution

    # Identify missing word positions
    MISSING_POSITIONS = [i for i, word in enumerate(KNOWN_WORDS) if word == "?"]
    MISSING_COUNT = len(MISSING_POSITIONS)

    if MISSING_COUNT == 0:
        logger.info("No missing words detected. The seed phrase is complete.")
        sys.exit(0)

    # Initialize BIP39 utilities
    mnemo = Mnemonic("english")
    wordlist = mnemo.wordlist

    # Log basic information
    logger.info(f"Target wallet address: {TARGET_WALLET_ADDRESS}")
    logger.info(f"Derivation path: {DERIVATION_PATH}")
    logger.info(f"Missing word count: {MISSING_COUNT}")
    logger.info(f"Total possible combinations: {len(wordlist) ** MISSING_COUNT:,}")


def is_valid_mnemonic(seed_phrase):
    """Validate mnemonic checksum using direct library functions"""
    try:
        # Use the built-in validation from the library
        return Mnemonic("english").check(seed_phrase)
    except Exception as e:
        if DEBUG_MODE:
            logger.debug(f"Error validating mnemonic: {str(e)}")
        return False


def batch_generate_valid_combinations(start_idx, count):
    """Generate valid combinations in batches - used by worker processes"""
    valid_combinations = []
    total_valid = 0
    total_invalid = 0

    # Generate all possible combinations
    all_combinations = list(product(wordlist, repeat=MISSING_COUNT))
    batch = all_combinations[start_idx:start_idx + count]

    for combo in batch:
        if found_seed.is_set():
            break

        temp_seed = KNOWN_WORDS.copy()
        for idx, pos in enumerate(MISSING_POSITIONS):
            temp_seed[pos] = combo[idx]

        full_seed = " ".join(temp_seed)

        # Validate the mnemonic
        if is_valid_mnemonic(full_seed):
            valid_combinations.append(combo)
            total_valid += 1
        else:
            total_invalid += 1

    # Update global counters
    with counter_lock:
        valid_mnemonics.value += total_valid
        skipped_invalid.value += total_invalid

    return valid_combinations


def process_valid_combinations(valid_combinations):
    """Process a batch of valid combinations to check against wallet address"""
    for combo in valid_combinations:
        if found_seed.is_set():
            return None

        # Create full seed phrase
        full_seed_phrase = KNOWN_WORDS.copy()
        for idx, pos in enumerate(MISSING_POSITIONS):
            full_seed_phrase[pos] = combo[idx]

        full_seed_phrase_str = " ".join(full_seed_phrase)

        # Derive wallet and check
        wallet_address = derive_pi_wallet(full_seed_phrase_str)

        with counter_lock:
            total_checked.value += 1

        if wallet_address and wallet_address == TARGET_WALLET_ADDRESS:
            found_seed.set()
            logger.info(f"Successfully Recovered Seed Phrase: {full_seed_phrase_str}")
            return full_seed_phrase_str

    return None


def derive_pi_wallet(seed_phrase):
    """Derive Pi Network wallet address from seed phrase"""
    try:
        seed_bytes = Bip39SeedGenerator(seed_phrase).Generate()
        private_key = Bip32Slip10Ed25519.FromSeed(seed_bytes).DerivePath(DERIVATION_PATH).PrivateKey().Raw().ToBytes()
        return StrKey.encode_ed25519_public_key(nacl.signing.SigningKey(private_key).verify_key.encode())
    except Exception as e:
        if DEBUG_MODE:
            logger.debug(f"Error deriving wallet address: {str(e)}")
        return None


def monitor_progress(fs, tc, si, vm, cl):
    """Display elapsed time and progress statistics"""
    # Assign shared variables from parameters
    global found_seed, total_checked, skipped_invalid, valid_mnemonics, counter_lock
    found_seed = fs
    total_checked = tc
    skipped_invalid = si
    valid_mnemonics = vm
    counter_lock = cl

    start_time = time.time()
    last_update_time = start_time
    last_checked = 0
    last_valid = 0
    last_skipped = 0

    try:
        while not found_seed.is_set():
            current_time = time.time()
            elapsed_seconds = current_time - start_time

            # Update every 5 seconds
            if current_time - last_update_time >= 5:
                with counter_lock:
                    current_checked = total_checked.value
                    current_skipped = skipped_invalid.value
                    current_valid = valid_mnemonics.value

                # Calculate speeds
                checked_since_last = current_checked - last_checked
                valid_since_last = current_valid - last_valid
                skipped_since_last = current_skipped - last_skipped

                check_speed = checked_since_last / (
                            current_time - last_update_time) if current_time != last_update_time else 0
                validation_speed = (valid_since_last + skipped_since_last) / (
                            current_time - last_update_time) if current_time != last_update_time else 0

                logger.info(
                    f"Elapsed: {elapsed_seconds:.2f}s | "
                    f"Checked: {current_checked:,} | "
                    f"Valid: {current_valid:,} | "
                    f"Skipped: {current_skipped:,} | "
                    f"Speed: {check_speed:.2f} checks/s | "
                    f"Validation: {validation_speed:.2f} phrases/s"
                )

                last_update_time = current_time
                last_checked = current_checked
                last_valid = current_valid
                last_skipped = current_skipped

            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("Progress monitoring stopped")


def terminate_processes(graceful=True):
    """Terminate all processes, with option for graceful shutdown"""
    logger.info("Terminating worker processes...")

    # Try graceful termination first
    for child in psutil.Process(os.getpid()).children(recursive=True):
        try:
            if graceful:
                child.terminate()
            else:
                child.kill()
        except psutil.NoSuchProcess:
            pass

    # Allow time for processes to terminate
    time.sleep(0.5)


def recover_seed(timeout=None):
    """Main recovery function with improved parallel processing"""
    global found_seed, total_checked, skipped_invalid, valid_mnemonics, counter_lock

    # Create manager here - inside the function not at module level
    manager = multiprocessing.Manager()
    found_seed = manager.Event()
    total_checked = manager.Value("i", 0)
    skipped_invalid = manager.Value("i", 0)
    valid_mnemonics = manager.Value("i", 0)
    counter_lock = manager.Lock()

    cpu_count = max(1, multiprocessing.cpu_count() - 1)
    logger.info(f"Starting seed phrase recovery process")
    logger.info(f"Using {cpu_count} CPU cores for processing")

    # Start progress monitoring in a separate process with shared variables
    progress_process = multiprocessing.Process(
        target=monitor_progress,
        args=(found_seed, total_checked, skipped_invalid, valid_mnemonics, counter_lock)
    )
    progress_process.daemon = True
    progress_process.start()

    start_time = time.time()
    result = None
    pool = None

    try:
        # Calculate total combinations and batch size for each worker
        total_combinations = len(wordlist) ** MISSING_COUNT

        # Process in manageable chunks
        step_size = min(1000000, max(BATCH_SIZE * 10, total_combinations // (cpu_count * 10)))

        pool = multiprocessing.Pool(
            processes=cpu_count,
            initializer=init_worker,
            initargs=(found_seed, total_checked, skipped_invalid, valid_mnemonics, counter_lock)
        )

        # First step: Find valid mnemonics in parallel batches
        logger.info(f"Generating and validating seed phrases...")

        for start_idx in range(0, total_combinations, step_size):
            if found_seed.is_set():
                break

            end_idx = min(start_idx + step_size, total_combinations)
            current_batch_size = end_idx - start_idx

            # Split the work into chunks for workers
            chunk_size = current_batch_size // cpu_count
            if chunk_size == 0:
                chunk_size = current_batch_size

            chunk_args = [(start_idx + i * chunk_size, min(chunk_size, current_batch_size - i * chunk_size))
                          for i in range(cpu_count) if i * chunk_size < current_batch_size]

            # Process each chunk to find valid mnemonics
            valid_batches = pool.starmap(batch_generate_valid_combinations, chunk_args)

            # Flatten the list of valid combinations
            valid_combinations = [combo for batch in valid_batches for combo in batch]

            if valid_combinations:
                logger.info(
                    f"Found {len(valid_combinations)} valid seed phrases in this batch, checking against wallet...")

                # Second step: Check these valid mnemonics against the wallet
                chunk_size = min(CHUNK_SIZE, len(valid_combinations))
                for i in range(0, len(valid_combinations), chunk_size):
                    chunk = valid_combinations[i:i + chunk_size]
                    res = process_valid_combinations(chunk)
                    if res:
                        result = res
                        found_seed.set()
                        break

            # Check timeout
            if timeout and (time.time() - start_time) > timeout:
                logger.info(f"Timeout reached after {timeout} seconds")
                found_seed.set()
                break

            # Report progress
            with counter_lock:
                logger.info(f"Processed {end_idx:,}/{total_combinations:,} combinations "
                            f"({end_idx / total_combinations * 100:.2f}%) - "
                            f"Found {valid_mnemonics.value:,} valid phrases so far")

    except KeyboardInterrupt:
        logger.info("Recovery process interrupted by user")
    finally:
        # Clean up
        found_seed.set()  # Signal all processes to stop

        if progress_process.is_alive():
            progress_process.terminate()
            progress_process.join(timeout=1)

        # Wait for processes to terminate cleanly
        if pool:
            pool.close()
            pool.join()

        # Final report
        try:
            with counter_lock:
                logger.info(f"Recovery complete. Checked {total_checked.value:,} valid seeds "
                            f"out of {valid_mnemonics.value:,} valid mnemonics found.")
        except Exception:
            logger.info("Recovery complete.")

        # Clean up manager
        manager.shutdown()

    return result


def main():
    """Main entry point with error handling"""
    try:
        # Initialize global variables
        initialize_globals()

        # Run recovery process
        recovered_seed = recover_seed()

        if recovered_seed:
            logger.info(f"Recovery successful! Seed phrase: {recovered_seed}")
            return 0
        else:
            logger.info("No matching seed phrase found")
            return 1

    except KeyboardInterrupt:
        logger.info("Process interrupted by user")
        terminate_processes()
        return 130
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}", exc_info=True)
        terminate_processes(graceful=False)
        return 1


if __name__ == "__main__":
    # Add freeze_support for Windows compatibility
    multiprocessing.freeze_support()
    sys.exit(main())