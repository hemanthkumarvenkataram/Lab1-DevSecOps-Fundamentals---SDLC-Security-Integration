# MCSC 6002 - Lab 1 Step-by-Step Guide

## Files to place in one folder
- `users.json` (original dataset)
- `users_tampered.json` (tampered dataset)
- `secure_users.py` (provided solution)

## 1. Confirm Python
Open Command Prompt / PowerShell / Terminal in the Lab1 folder:

```bash
python --version
```

If `python` is not recognized on Windows, try `py --version` and use `py` instead of `python` in the commands below.

## 2. Install the encryption dependency

```bash
python -m pip install cryptography
```

## 3. Initialize secure storage

```bash
python secure_users.py initialize
```

Expected behavior:
- Generates `lab1.key` if it does not exist.
- Creates `users_original_backup.json` once for lab comparison.
- Rewrites `users.json` so passwords are Fernet ciphertext.
- Adds `integrity_hash` (SHA-256) to every record.

Take screenshots showing the command succeeds and open `users.json` in VS Code to show encrypted passwords and hashes.

## 4. Add a new user (Task 2.a)

```bash
python secure_users.py add
```

Example values:
- Username: `frank`
- Password: `FrankSecure123!`
- Email: `frank@example.com`

The password is entered with a hidden prompt. Take a screenshot after the program confirms the user was stored securely.

## 5. Show encryption (Task 2.b)

```bash
python secure_users.py show
```

Confirm that the `password` field is a long Fernet ciphertext string, not the original plaintext password. Take a screenshot.

## 6. Show integrity hashes (Task 2.c)
Open `users.json` and show the `integrity_hash` field for multiple records. Each value should be a 64-character hexadecimal SHA-256 digest. Take a screenshot.

## 7. Verify clean records (Task 2.d)

```bash
python secure_users.py verify
```

Expected result:

```text
[VALID] alice
[VALID] bob
[VALID] carol
[VALID] dave
[VALID] eve
Integrity verification PASSED.
```

If you added another user, it should also appear as `[VALID]`.

## 8. Demonstrate the tampered file (Task 4.b)
Do not modify the supplied `users_tampered.json`. In the supplied files, Bob's original password is `BobSecure456`, while the tampered file contains `BobHacked999`.

Open the original backup (`users_original_backup.json`) and `users_tampered.json` side-by-side in VS Code and capture a screenshot of Bob's changed password.

## 9. Detect tampering (Tasks 4.a and 4.c)

```bash
python secure_users.py verify-tampered users_tampered.json
```

Expected key result:

```text
[VALID] alice
[TAMPERED] bob
[VALID] carol
[VALID] dave
[VALID] eve
Tampering detected: one or more records do not match the trusted baseline.
```

The program also prints Bob's expected and observed SHA-256 hashes. Take a screenshot showing `[TAMPERED] bob`.

## 10. What each security control demonstrates
- **Confidentiality:** Fernet encrypts password values before they are stored.
- **Integrity:** SHA-256 creates a deterministic fingerprint for each canonical record.
- **Verification:** the script recomputes hashes and compares them using `hmac.compare_digest`.
- **Input validation:** username, password length, email format, and duplicate usernames are checked.
- **Availability / robustness:** malformed JSON, missing files, missing keys, and invalid encrypted data are handled with clear errors; file writes use a temporary file followed by replacement.

## 11. Screenshots required in the report
Capture evidence for:
1. Task 2.a - adding a user.
2. Task 2.b - encrypted password in `users.json`.
3. Task 2.c - stored SHA-256 `integrity_hash` values.
4. Task 2.d - clean integrity verification passes.
5. Task 4.a - integrity verification / comparison functionality.
6. Task 4.b - Bob's changed password in the tampered file.
7. Task 4.c - `[TAMPERED] bob` detection result.

## 12. Submission
Submit the completed Lab 1 DOCX and `secure_users.py` as separate files. Follow the instruction not to submit a ZIP archive.
