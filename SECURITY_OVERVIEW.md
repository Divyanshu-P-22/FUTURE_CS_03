# Security Overview: Encryption Methods and Key Handling

## Table of Contents
1. [Encryption Architecture](#encryption-architecture)
2. [AES-256 Encryption Implementation](#aes-256-encryption-implementation)
3. [Key Management](#key-management)
4. [File Encryption Process](#file-encryption-process)
5. [File Decryption Process](#file-decryption-process)
6. [Security Considerations](#security-considerations)
7. [Best Practices](#best-practices)

---

## Encryption Architecture

The Flask Secure File Portal uses **AES-256 (Advanced Encryption Standard)** in **CBC (Cipher Block Chaining)** mode to encrypt all uploaded files before storage. This ensures that files are protected at rest and cannot be read without the encryption key.

### Why AES-256?

- **Industry Standard**: AES is the encryption standard adopted by the U.S. government and used worldwide
- **Strong Security**: 256-bit keys provide 2^256 possible keys, making brute-force attacks computationally infeasible
- **Performance**: Hardware-accelerated on modern processors, providing fast encryption/decryption
- **Proven Security**: Extensively analyzed and considered secure for sensitive data

### Why CBC Mode?

- **Security**: Each block's encryption depends on the previous block, preventing patterns in plaintext from appearing in ciphertext
- **Randomization**: Uses a unique Initialization Vector (IV) for each file, ensuring identical files produce different ciphertext
- **Compatibility**: Widely supported and well-understood mode

---

## AES-256 Encryption Implementation

### Encryption Algorithm Details

```python
# Key Size: 32 bytes (256 bits)
# Block Size: 16 bytes (128 bits)
# Mode: CBC (Cipher Block Chaining)
# Padding: PKCS7 (automatic via pad/unpad functions)
```

### Code Implementation

The encryption is implemented in the `encrypt_file()` function:

```python
def encrypt_file(file_data):
    """Encrypt file data using AES-256 in CBC mode"""
    # 1. Retrieve or generate the encryption key (32 bytes)
    key = get_encryption_key()
    
    # 2. Create AES cipher in CBC mode (generates random IV automatically)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # IV is 16 bytes (one block size)
    
    # 3. Pad data to match AES block size (16 bytes)
    # PKCS7 padding ensures data length is multiple of block size
    padded_data = pad(file_data, AES.block_size)
    
    # 4. Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    # 5. Prepend IV to encrypted data (IV needed for decryption)
    # Format: [IV (16 bytes)][Encrypted Data (variable length)]
    return iv + encrypted_data
```

### Encryption Flow Diagram

```
Original File
    ↓
Read File Data (bytes)
    ↓
Generate/Retrieve 256-bit Key
    ↓
Create AES-256-CBC Cipher
    ↓
Generate Random IV (16 bytes)
    ↓
Pad Data to Block Size (PKCS7)
    ↓
Encrypt Padded Data
    ↓
Prepend IV to Ciphertext
    ↓
Save: [IV][Ciphertext] → filename.enc
```

---

## Key Management

### Key Generation

The encryption key is generated using cryptographically secure random number generation:

```python
def get_encryption_key():
    """Get or generate encryption key for file encryption"""
    key_file = Path('keys/encryption_key.key')
    
    if key_file.exists():
        # Load existing key
        with open(key_file, 'rb') as f:
            return f.read()
    else:
        # Generate new 256-bit (32-byte) random key
        key = get_random_bytes(32)
        
        # Save key for future use
        with open(key_file, 'wb') as f:
            f.write(key)
        
        return key
```

### Key Characteristics

- **Size**: 32 bytes (256 bits)
- **Generation**: Cryptographically secure random (`Crypto.Random.get_random_bytes`)
- **Storage**: Stored in `keys/encryption_key.key` file
- **Persistence**: Key is generated once and reused for all files

### Key Security Properties

1. **Randomness**: Uses `Crypto.Random.get_random_bytes()`, which provides cryptographically secure random numbers suitable for cryptographic keys
2. **Uniqueness**: Each application instance generates a unique key
3. **Persistence**: Key is saved to disk to ensure consistent encryption/decryption across application restarts

### ⚠️ Current Key Storage (Development)

**Current Implementation:**
- Key is stored as a plain file in the `keys/` directory
- No additional encryption of the key itself
- Accessible to anyone with file system access

**Production Recommendations:**
- Store keys in environment variables
- Use a Hardware Security Module (HSM)
- Use a Key Management Service (KMS) like AWS KMS, Azure Key Vault, or HashiCorp Vault
- Encrypt the key file itself with a master key
- Implement key rotation policies

---

## File Encryption Process

### Step-by-Step Encryption

1. **File Upload**
   - User uploads a file through the web interface
   - File is received by Flask as a file object

2. **Filename Sanitization**
   ```python
   filename = secure_filename(file.filename)
   ```
   - Removes dangerous characters and path components
   - Prevents directory traversal attacks

3. **File Reading**
   ```python
   file_data = file.read()  # Read entire file into memory as bytes
   ```

4. **Encryption**
   ```python
   encrypted_data = encrypt_file(file_data)
   ```
   - Generates/retrieves encryption key
   - Creates AES-256-CBC cipher with random IV
   - Pads data to block size
   - Encrypts data
   - Prepends IV to ciphertext

5. **Storage**
   ```python
   encrypted_filename = filename + '.enc'
   file_path = Path(app.config['UPLOAD_FOLDER']) / encrypted_filename
   with open(file_path, 'wb') as f:
       f.write(encrypted_data)
   ```
   - Saves encrypted data to disk
   - Original filename preserved in encrypted filename (without extension)
   - File extension changed to `.enc` to indicate encrypted status

### Encrypted File Format

```
[16 bytes: IV][Variable length: Encrypted File Data]
```

- **IV (Initialization Vector)**: First 16 bytes
  - Random value unique to each file
  - Ensures identical files produce different ciphertext
  - Not secret, but must be unique and unpredictable
  
- **Encrypted Data**: Remaining bytes
  - Original file data encrypted with AES-256-CBC
  - Includes PKCS7 padding
  - Size is original size + padding (rounded up to nearest 16 bytes)

### Example

**Original File**: `document.pdf` (1,234 bytes)

**Encryption Process**:
1. Read 1,234 bytes
2. Pad to 1,248 bytes (multiple of 16)
3. Generate random 16-byte IV
4. Encrypt 1,248 bytes → 1,248 bytes ciphertext
5. Prepend 16-byte IV
6. **Total encrypted file**: 1,264 bytes

**Stored as**: `document.pdf.enc` (1,264 bytes)

---

## File Decryption Process

### Step-by-Step Decryption

1. **File Request**
   - User requests download of a file
   - Application validates filename and path

2. **File Reading**
   ```python
   with open(file_path, 'rb') as f:
       encrypted_data = f.read()
   ```
   - Reads entire encrypted file from disk

3. **IV Extraction**
   ```python
   iv = encrypted_data[:16]  # First 16 bytes are IV
   ciphertext = encrypted_data[16:]  # Rest is encrypted data
   ```

4. **Decryption**
   ```python
   decrypted_data = decrypt_file(encrypted_data)
   ```
   - Retrieves encryption key
   - Extracts IV from first 16 bytes
   - Creates AES-256-CBC cipher with same key and IV
   - Decrypts ciphertext
   - Removes PKCS7 padding

5. **Delivery**
   ```python
   file_obj = BytesIO(decrypted_data)
   return send_file(file_obj, as_attachment=True, download_name=filename)
   ```
   - Creates in-memory file object
   - Sends decrypted file to user
   - Original filename restored

### Decryption Code

```python
def decrypt_file(encrypted_data):
    """Decrypt file data using AES-256 in CBC mode"""
    # 1. Retrieve the encryption key
    key = get_encryption_key()
    
    # 2. Extract IV (first 16 bytes) and ciphertext (remaining bytes)
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    
    # 3. Create AES cipher with same key and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    
    # 4. Decrypt the ciphertext
    decrypted_data = cipher.decrypt(ciphertext)
    
    # 5. Remove PKCS7 padding to get original data
    return unpad(decrypted_data, AES.block_size)
```

---

## Security Considerations

### Strengths

1. **Strong Encryption**: AES-256 is considered secure against current and foreseeable threats
2. **Unique IVs**: Each file uses a unique IV, preventing pattern analysis
3. **Secure Key Generation**: Uses cryptographically secure random number generation
4. **Path Validation**: Prevents directory traversal attacks
5. **Filename Sanitization**: Prevents injection attacks through filenames

### Current Limitations

1. **Key Storage**: Key stored as plain file (see recommendations above)
2. **Single Key**: All files encrypted with same key (consider per-file keys for enhanced security)
3. **No Key Rotation**: Key persists indefinitely (implement rotation policy)
4. **In-Memory Keys**: Keys exist in memory during encryption/decryption (consider secure memory handling)

### Threat Model

**Protected Against:**
- ✅ Unauthorized file access (without key)
- ✅ File tampering (encryption ensures integrity)
- ✅ Pattern analysis (unique IVs)
- ✅ Directory traversal attacks
- ✅ Filename injection attacks

**Not Protected Against (Current Implementation):**
- ❌ Key file theft (if attacker has file system access)
- ❌ Memory dumps (keys in memory during operation)
- ❌ Compromised server (attacker with server access can access key)
- ❌ Key loss (if key file deleted, all files become unrecoverable)

---

## Best Practices

### For Development

1. **Never commit keys to version control**
   - Add `keys/` to `.gitignore`
   - Never share keys in code repositories

2. **Use environment variables for secrets**
   ```python
   import os
   SECRET_KEY = os.environ.get('SECRET_KEY', secrets.token_hex(32))
   ```

3. **Test with different keys**
   - Ensure application handles key changes gracefully
   - Test key generation and loading

### For Production

1. **Key Management Service**
   - Use AWS KMS, Azure Key Vault, or similar
   - Implement key rotation policies
   - Use separate keys for different environments

2. **Key Backup and Recovery**
   - Securely backup encryption keys
   - Store backups in separate secure location
   - Document key recovery procedures

3. **Access Control**
   - Restrict file system access to key files
   - Use file permissions (chmod 600)
   - Implement application-level access controls

4. **Monitoring**
   - Log encryption/decryption operations
   - Monitor for unauthorized access attempts
   - Alert on key access anomalies

5. **Key Rotation**
   - Implement periodic key rotation
   - Re-encrypt files with new keys
   - Maintain old keys for decryption of legacy files

6. **Secure Memory Handling**
   - Clear keys from memory after use (where possible)
   - Use secure memory allocation
   - Prevent memory dumps

### Key Rotation Example

```python
def rotate_encryption_key():
    """Rotate encryption key and re-encrypt all files"""
    old_key = get_encryption_key()
    new_key = get_random_bytes(32)
    
    # Re-encrypt all files with new key
    for encrypted_file in Path('protected_files').glob('*.enc'):
        # Decrypt with old key
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        decrypted_data = decrypt_with_key(encrypted_data, old_key)
        
        # Encrypt with new key
        new_encrypted_data = encrypt_with_key(decrypted_data, new_key)
        
        # Save re-encrypted file
        with open(encrypted_file, 'wb') as f:
            f.write(new_encrypted_data)
    
    # Save new key
    with open('keys/encryption_key.key', 'wb') as f:
        f.write(new_key)
    
    # Archive old key for legacy file access
    archive_key(old_key)
```

---

## Technical Specifications

### Encryption Parameters

| Parameter | Value | Description |
|-----------|-------|-------------|
| Algorithm | AES | Advanced Encryption Standard |
| Key Size | 256 bits (32 bytes) | Provides 2^256 possible keys |
| Block Size | 128 bits (16 bytes) | Standard AES block size |
| Mode | CBC | Cipher Block Chaining |
| Padding | PKCS7 | Standard padding scheme |
| IV Size | 128 bits (16 bytes) | One block size |
| IV Generation | Random | Cryptographically secure random |

### File Format

| Offset | Size | Content |
|--------|------|---------|
| 0x00 | 16 bytes | Initialization Vector (IV) |
| 0x10 | Variable | Encrypted file data (with padding) |

### Performance Characteristics

- **Encryption Speed**: ~100-500 MB/s (hardware-dependent)
- **Overhead**: ~16 bytes per file (IV) + padding (0-15 bytes)
- **Memory Usage**: File size + ~48 bytes (key + IV + cipher objects)

---

## Conclusion

The Flask Secure File Portal implements robust AES-256 encryption to protect files at rest. The encryption implementation follows industry best practices with proper IV usage, secure key generation, and standard padding. For production use, implement the recommended key management improvements to enhance security further.

**Key Takeaways:**
- ✅ Strong encryption (AES-256)
- ✅ Proper IV usage (unique per file)
- ✅ Secure key generation
- ⚠️ Key storage needs improvement for production
- ⚠️ Consider key rotation and backup strategies

---

**Document Version**: 1.0  
**Last Updated**: [Current Date]  
**Maintained By**: Development Team

