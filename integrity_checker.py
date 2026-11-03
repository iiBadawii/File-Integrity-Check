# File Integrity Checker using SHA-256
# Security service implemented: DATA INTEGRITY
#
# The program saves the SHA-256 hash of a file and later recalculates the
# hash to detect whether the file has changed. It uses only Python's
# standard library.

import os

# The SHA-256 algorithm is implemented by hand in this file (no hashlib).

# Every calculation is done on 32-bit numbers. Python integers can grow
# without limit, so we use this mask to cut results back to 32 bits.
MASK_32_BITS = 0xFFFFFFFF

# Starting values defined by the SHA-256 standard (FIPS 180-4).
# They are the first 32 bits of the square roots of the first 8 primes.
INITIAL_HASH_VALUES = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

# 64 constants defined by the standard, one for each round of mixing.
# They are the first 32 bits of the cube roots of the first 64 primes.
ROUND_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]


def rotate_right(value, amount):
    """Rotate a 32-bit number right: bits that fall off the right end
    re-enter on the left. SHA-256 uses this to mix bits thoroughly."""
    moved_right = value >> amount
    moved_left = (value << (32 - amount)) & MASK_32_BITS
    return moved_right | moved_left

def pad_message(data):
    """Pad the data so its length is a multiple of 64 bytes (512 bits).
    SHA-256 processes data in fixed 64-byte blocks."""
    original_length_in_bits = len(data) * 8

    # Step 1: add a single 1-bit (the byte 0x80 = 10000000 in binary).
    padded_data = data + b"\x80"

    # Step 2: add zero bytes until exactly 8 bytes remain in the block.
    while len(padded_data) % 64 != 56:
        padded_data = padded_data + b"\x00"

    # Step 3: add the original length (in bits) as an 8-byte number.
    # Including the length means messages of different lengths never
    # become identical after padding.
    padded_data = padded_data + original_length_in_bits.to_bytes(8, "big")
    return padded_data


def process_block(block, hash_values):
    """Mix one 64-byte block into the 8 running hash values."""
    # Part 1: build the "message schedule" of 64 words (32-bit numbers).
    # The first 16 words come directly from the block's bytes.
    words = []
    for index in range(16):
        start = index * 4
        words.append(int.from_bytes(block[start:start + 4], "big"))

    # The other 48 words are created by mixing earlier words together.
    # This spreads every input bit across the whole calculation.
    for index in range(16, 64):
        older = words[index - 15]
        newer = words[index - 2]
        small_sigma0 = rotate_right(older, 7) ^ rotate_right(older, 18) ^ (older >> 3)
        small_sigma1 = rotate_right(newer, 17) ^ rotate_right(newer, 19) ^ (newer >> 10)
        new_word = words[index - 16] + small_sigma0 + words[index - 7] + small_sigma1
        words.append(new_word & MASK_32_BITS)

    # Part 2: 64 rounds of mixing, using 8 working variables a to h.
    a, b, c, d, e, f, g, h = hash_values
    for index in range(64):
        big_sigma1 = rotate_right(e, 6) ^ rotate_right(e, 11) ^ rotate_right(e, 25)
        choose = (e & f) ^ (~e & g)
        temp1 = h + big_sigma1 + choose + ROUND_CONSTANTS[index] + words[index]
        big_sigma0 = rotate_right(a, 2) ^ rotate_right(a, 13) ^ rotate_right(a, 22)
        majority = (a & b) ^ (a & c) ^ (b & c)
        temp2 = big_sigma0 + majority

        # Shift all variables along by one position, mixing in the new values.
        h = g
        g = f
        f = e
        e = (d + temp1) & MASK_32_BITS
        d = c
        c = b
        b = a
        a = (temp1 + temp2) & MASK_32_BITS

    # Part 3: add this block's result to the running hash values.
    mixed_values = [a, b, c, d, e, f, g, h]
    new_hash_values = []
    for index in range(8):
        new_hash_values.append((hash_values[index] + mixed_values[index]) & MASK_32_BITS)
    return new_hash_values


def sha256_from_scratch(data):
    """Return the SHA-256 hash of some bytes as 64 hex characters."""
    hash_values = list(INITIAL_HASH_VALUES)
    padded_data = pad_message(data)

    # Process the padded data one 64-byte block at a time.
    for start in range(0, len(padded_data), 64):
        block = padded_data[start:start + 64]
        hash_values = process_block(block, hash_values)

    # Convert the 8 final numbers into text, 8 hex digits for each number.
    hex_text = ""
    for value in hash_values:
        hex_text = hex_text + format(value, "08x")
    return hex_text


def calculate_file_hash(file_path):
    """Return the SHA-256 hash of a file as a 64-character hex string."""
    # "rb" = read binary. Hashing works on raw bytes, so binary mode lets us
    # handle ANY file type (text, images, PDFs, programs) without Python
    # changing the bytes (for example, converting line endings).
    with open(file_path, "rb") as file_to_hash:
        file_bytes = file_to_hash.read()

    return sha256_from_scratch(file_bytes)


def get_reference_path(file_path):
    """Return the name of the file where the reference hash is stored."""
    # Example: "report.txt" -> "report.txt.sha256" (saved next to the file).
    return file_path + ".sha256"


def ask_for_existing_file():
    """Ask the user for a file path. Return the path, or None if invalid."""
    file_path = input("Enter the path of the file: ").strip()

    # Windows "Copy as path" adds quotation marks, so we remove them.
    file_path = file_path.strip('"')

    if file_path == "":
        print("Error: You did not enter a path.")
        return None
    if not os.path.exists(file_path):
        print("Error: The file does not exist: " + file_path)
        return None
    if not os.path.isfile(file_path):
        print("Error: The path is not a file (it may be a folder): " + file_path)
        return None
    return file_path


def try_to_calculate_hash(file_path):
    """Calculate a file's hash. Return None if the file cannot be read."""
    try:
        return calculate_file_hash(file_path)
    except OSError:
        # OSError covers problems such as "permission denied".
        print("Error: The file could not be read (check its permissions).")
        return None
    except MemoryError:
        # The whole file is loaded into memory, so a huge file can fail.
        print("Error: The file is too large to process.")
        return None


def save_reference_hash(reference_path, hash_value):
    """Write the hash to the reference file. Return True if it worked."""
    try:
        with open(reference_path, "w") as reference_file:
            reference_file.write(hash_value)
        return True
    except OSError:
        print("Error: The reference hash could not be saved.")
        return False


def read_reference_hash(reference_path):
    """Read the saved hash. Return None (with a message) if it is unusable."""
    if not os.path.isfile(reference_path):
        print("Error: No saved reference hash was found for this file.")
        print("Expected reference file: " + reference_path)
        print("Use option 1 first to calculate and save a hash.")
        return None

    try:
        with open(reference_path, "r") as reference_file:
            # strip() removes spaces/newlines; lower() makes the comparison
            # work even if someone typed the hash in capital letters.
            saved_hash = reference_file.read().strip().lower()
    except (OSError, UnicodeDecodeError):
        print("Error: The reference hash file could not be read.")
        return None

    # A SHA-256 hash in hex is always exactly 64 characters long.
    if len(saved_hash) != 64:
        print("Error: The reference file is damaged (it is not a SHA-256 hash).")
        return None
    return saved_hash


def option_save_hash():
    """Menu option 1: calculate the hash and save it as the reference."""
    file_path = ask_for_existing_file()
    if file_path is None:
        return

    reference_path = get_reference_path(file_path)

    # Overwriting an old reference would destroy the proof of the original
    # file, so we ask for confirmation first.
    if os.path.exists(reference_path):
        answer = input("A reference hash already exists. Overwrite it? (y/n): ")
        if answer.strip().lower() != "y":
            print("Cancelled. The existing reference hash was not changed.")
            return

    hash_value = try_to_calculate_hash(file_path)
    if hash_value is None:
        return

    if save_reference_hash(reference_path, hash_value):
        print("SHA-256 hash: " + hash_value)
        print("Reference hash saved to: " + reference_path)


def option_verify_hash():
    """Menu option 2: compare the file's current hash with the saved one."""
    file_path = ask_for_existing_file()
    if file_path is None:
        return

    saved_hash = read_reference_hash(get_reference_path(file_path))
    if saved_hash is None:
        return

    current_hash = try_to_calculate_hash(file_path)
    if current_hash is None:
        return

    print("Saved hash:   " + saved_hash)
    print("Current hash: " + current_hash)

    # Identical hashes mean the file content is identical. Any difference
    # means the content has changed.
    if current_hash == saved_hash:
        print("RESULT: The file is UNCHANGED. Its integrity is verified.")
    else:
        print("RESULT: WARNING - The file has been MODIFIED since the hash was saved!")


def option_display_hash():
    """Menu option 3: show the hash without saving anything."""
    file_path = ask_for_existing_file()
    if file_path is None:
        return

    hash_value = try_to_calculate_hash(file_path)
    if hash_value is not None:
        print("SHA-256 hash: " + hash_value)


def show_menu():
    print()
    print("==============================")
    print(" File Integrity Checker (SHA-256)")
    print("==============================")
    print("1. Calculate and save the SHA-256 hash of a file")
    print("2. Verify a file against its saved hash")
    print("3. Display the SHA-256 hash of a file (without saving)")
    print("4. Exit")


def main():
    # The loop repeats until the user chooses option 4.
    while True:
        show_menu()
        choice = input("Enter your choice (1-4): ").strip()
        print()

        if choice == "1":
            option_save_hash()
        elif choice == "2":
            option_verify_hash()
        elif choice == "3":
            option_display_hash()
        elif choice == "4":
            print("Goodbye!")
            break
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")


# This runs main() only when the file is executed directly,
# not when it is imported by another program.
if __name__ == "__main__":
    main()