# File Integrity Checker Using SHA-256

**Course:** ECE4113 Secure Software Development
**Authors:** _[Student 1 name, ID]_ and _[Student 2 name, ID]_

## 1. Objective

Build a simple command-line tool that detects unauthorized changes to files by comparing SHA-256 hashes. The program uses only Python's standard library.

## 2. Security Service Implemented: Data Integrity

Data integrity means information has not been altered, deleted, or corrupted since a trusted point in time. This program supports integrity by **detecting** changes: it saves a reference hash of a file and later recalculates the hash to see whether the content still matches.

## 3. Background: SHA-256 and Cryptographic Hashes

A **cryptographic hash function** turns input of any size into a fixed-size "fingerprint". **SHA-256** always produces 256 bits, shown as 64 hexadecimal characters. Its key properties:

- **Deterministic:** the same input always gives the same hash.
- **Avalanche effect:** changing even one bit of input completely changes the hash.
- **One-way:** it is infeasible to recover the input from the hash.
- **Collision resistant:** it is infeasible to find two different inputs with the same hash.

SHA-256 is a **hash function, not an encryption algorithm**. Encryption is reversible with a key and hides content; hashing is not reversible and has no key. It proves nothing is hidden; it only produces a fingerprint.

## 4. How the Program Detects Modification

1. **Save (option 1):** the program reads the file in binary mode, calculates its SHA-256 hash, and writes it to `<filename>.sha256` next to the file.
2. **Verify (option 2):** the program recalculates the file's current hash and compares it with the saved one.
3. **Result:** identical hashes mean the file is unchanged. Any difference means it has been modified.

## 5. Features

- Calculate and save a file's SHA-256 hash (option 1)
- Verify a file against its saved hash (option 2)
- Display a file's hash without saving (option 3)
- Works with any file type (binary reading) and large files (chunked reading)
- Handles nonexistent files, folders, empty paths, unreadable files, missing or damaged reference hashes, and invalid menu input
- Asks before overwriting an existing reference hash

## 6. Requirements

- Python 3.6 or newer
- No external packages, database, web server, or GUI

## 7. How to Run

Put `integrity_checker.py` in a folder and open a terminal in that folder.

**Windows (Command Prompt or PowerShell):**

```
python integrity_checker.py
```

(If `python` is not recognized, try `py integrity_checker.py`.)

**Linux / macOS:**

```
python3 integrity_checker.py
```

Choose options 1-4 from the menu. When asked, enter the file path (relative like `sample.txt`, or full like `C:\Users\me\sample.txt` or `/home/me/sample.txt`).

## 8. Example Usage

```
==============================
 File Integrity Checker (SHA-256)
==============================
1. Calculate and save the SHA-256 hash of a file
2. Verify a file against its saved hash
3. Display the SHA-256 hash of a file (without saving)
4. Exit
Enter your choice (1-4): 1

Enter the path of the file: sample.txt
SHA-256 hash: 2c526d1580514f262032eacd27d5b35504105ad69054a5d921dacc2b9aad424c
Reference hash saved to: sample.txt.sha256
```

Verifying the unchanged file (option 2):

```
Enter the path of the file: sample.txt
Saved hash:   2c526d1580514f262032eacd27d5b35504105ad69054a5d921dacc2b9aad424c
Current hash: 2c526d1580514f262032eacd27d5b35504105ad69054a5d921dacc2b9aad424c
RESULT: The file is UNCHANGED. Its integrity is verified.
```

Verifying after the file was modified:

```
Enter the path of the file: sample.txt
Saved hash:   2c526d1580514f262032eacd27d5b35504105ad69054a5d921dacc2b9aad424c
Current hash: a663858eacb0ea859903542455eeb69168c51f7742ad5979a204b1403b9f9007
RESULT: WARNING - The file has been MODIFIED since the hash was saved!
```

## 9. How to Test

Create the test file in the same folder as the program.

**Linux / macOS:**

```
echo "This is my important file." > sample.txt
```

**Windows (Command Prompt):**

```
echo This is my important file.> sample.txt
```

> The exact hash values in this README come from Linux. On Windows, line endings differ (CRLF instead of LF), so your hash will be different. This is normal; what matters is whether the saved and current hashes match.

### Test 1: Unchanged file

1. Run the program, choose **1**, enter `sample.txt`.
2. Choose **2**, enter `sample.txt`.

**Expected:** both hashes are identical and the program prints `RESULT: The file is UNCHANGED. Its integrity is verified.`

### Test 2: Modified file

1. Complete Test 1 first (hash saved).
2. Close the program and modify the file.
   - Linux/macOS: `echo "Someone added this line." >> sample.txt`
   - Windows: `echo Someone added this line.>> sample.txt`
3. Run the program, choose **2**, enter `sample.txt`.

**Expected:** the hashes are different and the program prints `RESULT: WARNING - The file has been MODIFIED since the hash was saved!`

### Test 3: Missing reference hash

1. Create a new file with no saved hash: `echo test > other.txt` (both systems).
2. Choose **2**, enter `other.txt`.

**Expected:**

```
Error: No saved reference hash was found for this file.
Expected reference file: other.txt.sha256
Use option 1 first to calculate and save a hash.
```

### Test 4: Invalid file path

1. Choose **1**, **2**, or **3**, enter `nofile.txt` (a file that does not exist).

**Expected:** `Error: The file does not exist: nofile.txt` and the menu appears again (the program does not crash).

### Additional checks

- Enter `7` at the menu: `Invalid choice. Please enter 1, 2, 3, or 4.`
- Enter the name of a folder: `Error: The path is not a file (it may be a folder): ...`
- Choose **1** for a file that already has a reference hash: the program asks `Overwrite it? (y/n)`.

## 10. Limitations and Security Considerations

- **Detects, does not prevent.** The program cannot stop anyone from modifying a file.
- **Does not identify who changed the file,** when, or what exactly changed. It only reports that the content differs.
- **The reference hash must be protected.** If an attacker can modify both the file and its `.sha256` file, they can replace the hash with the one for their modified file, and verification will falsely pass. For a trustworthy check, store the reference hash on read-only media, a separate secured system, or somewhere the attacker cannot write.
- **A plain hash has no secret key,** so anyone can compute it. Stronger designs use an **HMAC** (hash plus a secret key) or a **digital signature**, which an attacker without the key cannot forge.
- The check is only meaningful if the reference hash was saved while the file was still known to be good.
- Renaming or moving a file separates it from its `.sha256` file, so verification will report a missing reference hash.
- Only one file is checked at a time; there is no folder scanning, logging, or alerts.

## 11. AI Assistance Acknowledgment

_This project was developed with assistance from an AI tool (Claude by Anthropic), which was used to help generate the initial source code, README, and study materials. The authors reviewed, tested, and understand all of the code and can explain it. [Adjust this wording to accurately reflect the assistance you actually used.]_

## 12. Files

| File | Purpose |
|---|---|
| `integrity_checker.py` | The complete program |
| `README.md` | This documentation |
| `<name>.sha256` | Reference hash created by the program for each saved file |
