# Walkthrough Video Script: Flask Secure File Portal

## Video Overview
**Duration**: 10-15 minutes  
**Target Audience**: Developers, Security Professionals, Students  
**Purpose**: Demonstrate the application's features, architecture, and encryption implementation

---

## Script Outline

### 1. Introduction (0:00 - 1:00)
**Visual**: Application homepage/login screen

**Narration:**
"Welcome to this walkthrough of the Flask Secure File Portal. This is a secure web application that provides user authentication and encrypted file storage. In this video, we'll explore the application's features, demonstrate how it works, and dive deep into the encryption implementation that keeps your files secure."

**Key Points:**
- What the application does
- Main features to be covered
- What viewers will learn

---

### 2. Application Overview (1:00 - 2:30)
**Visual**: Navigate through the application interface

**Narration:**
"Let me start by showing you the application structure. The Flask Secure File Portal is built with Python Flask and provides a clean, modern web interface for secure file management."

**Demonstrations:**
- Show login page
- Explain authentication system
- Show dashboard interface
- Highlight key UI elements

**Narration:**
"The application uses Flask-Login for session management and Werkzeug for password hashing. All file operations require authentication, ensuring only authorized users can upload or download files."

---

### 3. User Authentication Flow (2:30 - 4:00)
**Visual**: Login process demonstration

**Narration:**
"Let's walk through the authentication process. When a user logs in, their credentials are verified against our user database. Passwords are hashed using Werkzeug's secure password hashing, which uses bcrypt under the hood."

**Actions:**
1. Enter credentials (admin/admin123)
2. Show successful login
3. Explain session creation
4. Show dashboard access

**Narration:**
"Once authenticated, Flask-Login creates a secure session. The session cookie stores the user ID, and all protected routes check for authentication before allowing access. Notice how we're automatically redirected to the dashboard after login."

**Code Highlight:**
- Show login route in app.py
- Explain password verification
- Show @login_required decorator

---

### 4. File Upload and Encryption (4:00 - 7:00)
**Visual**: Upload a file and show encryption process

**Narration:**
"Now let's see the core feature - file encryption. When a user uploads a file, it goes through several security steps before being stored."

**Step-by-Step Demonstration:**

**Step 1: File Selection**
- Select a test file (e.g., document.pdf)
- Show file input interface

**Narration:**
"First, the user selects a file to upload. The application validates that a file was selected and checks the file size against our 16MB limit."

**Step 2: Filename Sanitization**
**Code Highlight:**
```python
filename = secure_filename(file.filename)
```

**Narration:**
"The filename is sanitized using Werkzeug's secure_filename function. This removes dangerous characters and path components, preventing directory traversal attacks like '../etc/passwd'."

**Step 3: File Reading**
**Code Highlight:**
```python
file_data = file.read()  # Read file as bytes
```

**Narration:**
"The file is read into memory as raw bytes. This binary data is what we'll encrypt."

**Step 4: Encryption Process**
**Code Highlight:**
```python
def encrypt_file(file_data):
    key = get_encryption_key()  # 32-byte (256-bit) key
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv  # Random 16-byte IV
    padded_data = pad(file_data, AES.block_size)
    encrypted_data = cipher.encrypt(padded_data)
    return iv + encrypted_data
```

**Narration:**
"Here's where the magic happens. The encryption process uses AES-256 in CBC mode. Let me break this down:

1. We retrieve or generate a 256-bit encryption key
2. We create an AES cipher in CBC mode, which automatically generates a random 16-byte Initialization Vector, or IV
3. The file data is padded to match AES's 16-byte block size using PKCS7 padding
4. The padded data is encrypted
5. The IV is prepended to the encrypted data, because we'll need it for decryption

The IV ensures that even if you upload the same file twice, the encrypted versions will be completely different, preventing pattern analysis."

**Visual**: Show encrypted file in protected_files directory

**Narration:**
"Notice the file is saved with a .enc extension, indicating it's encrypted. The original filename is preserved, but the file content is now completely encrypted and unreadable without the key."

---

### 5. Key Management (7:00 - 8:30)
**Visual**: Show keys directory and key file

**Narration:**
"Let's talk about key management. The encryption key is critical - without it, encrypted files cannot be decrypted."

**Code Highlight:**
```python
def get_encryption_key():
    key_file = Path('keys/encryption_key.key')
    if key_file.exists():
        return f.read()  # Load existing key
    else:
        key = get_random_bytes(32)  # Generate new 256-bit key
        f.write(key)  # Save for future use
        return key
```

**Narration:**
"The key is generated using cryptographically secure random number generation. It's 32 bytes long, which gives us 256 bits - that's 2 to the power of 256 possible keys, making brute force attacks computationally infeasible.

The key is stored in the keys directory and persists across application restarts. This ensures that files encrypted today can still be decrypted tomorrow using the same key.

**Important Security Note**: In production, you should use a proper key management service like AWS KMS or Azure Key Vault, rather than storing keys as plain files. The current implementation is suitable for development but needs enhancement for production use."

---

### 6. File Download and Decryption (8:30 - 10:00)
**Visual**: Download the previously uploaded file

**Narration:**
"Now let's see how files are decrypted when a user downloads them."

**Step-by-Step Demonstration:**

**Step 1: File Request**
- Click download button for uploaded file

**Narration:**
"When a user requests a file download, the application first validates the filename and checks that the user is authenticated."

**Step 2: Path Validation**
**Code Highlight:**
```python
def is_safe_path(basedir, path):
    resolved_path = Path(basedir).resolve() / path
    return Path(basedir).resolve() in resolved_path.parents
```

**Narration:**
"The filename is validated to prevent directory traversal attacks. This ensures users can only access files within the intended directory."

**Step 3: Reading Encrypted File**
**Code Highlight:**
```python
with open(file_path, 'rb') as f:
    encrypted_data = f.read()
```

**Narration:**
"The encrypted file is read from disk. Remember, this file contains the IV followed by the encrypted data."

**Step 4: Decryption Process**
**Code Highlight:**
```python
def decrypt_file(encrypted_data):
    key = get_encryption_key()
    iv = encrypted_data[:16]  # Extract IV
    ciphertext = encrypted_data[16:]  # Extract encrypted data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    decrypted_data = cipher.decrypt(ciphertext)
    return unpad(decrypted_data, AES.block_size)
```

**Narration:**
"The decryption process reverses the encryption:

1. We retrieve the same encryption key used for encryption
2. We extract the IV from the first 16 bytes of the encrypted file
3. We extract the ciphertext from the remaining bytes
4. We create an AES cipher with the same key and IV
5. We decrypt the ciphertext
6. We remove the PKCS7 padding to get the original file data

The decrypted file is then sent to the user with the original filename restored."

**Visual**: Show downloaded file opens correctly

**Narration:**
"As you can see, the file downloads and opens correctly, confirming that the encryption and decryption process works perfectly."

---

### 7. Security Features Summary (10:00 - 12:00)
**Visual**: Code walkthrough of security features

**Narration:**
"Let me summarize the security features implemented in this application:"

**Security Feature 1: Authentication**
- Show login_required decorators
- Explain session management

**Security Feature 2: Password Hashing**
**Code Highlight:**
```python
generate_password_hash('password')
check_password_hash(hashed, 'password')
```

**Narration:**
"Passwords are never stored in plain text. They're hashed using Werkzeug's secure password hashing, which uses bcrypt - a slow, computationally expensive hashing algorithm designed specifically for password storage."

**Security Feature 3: Path Validation**
- Show is_safe_path function
- Explain directory traversal prevention

**Security Feature 4: Filename Sanitization**
- Show secure_filename usage
- Explain injection prevention

**Security Feature 5: File Encryption**
- Recap encryption process
- Emphasize AES-256 strength

**Narration:**
"Together, these features provide multiple layers of security, protecting both user accounts and file data."

---

### 8. Architecture Overview (12:00 - 13:00)
**Visual**: Show file structure and code organization

**Narration:**
"Let me give you a quick overview of the application architecture:"

**File Structure:**
```
flask-secure-app/
├── app.py              # Main application and routes
├── templates/          # HTML templates
├── static/            # CSS and JavaScript
├── protected_files/   # Encrypted file storage
└── keys/              # Encryption keys
```

**Narration:**
"The application follows a clean, organized structure. The main Flask application is in app.py, which handles routing, authentication, and encryption logic. Templates provide the user interface, and static files handle styling and client-side interactions."

**Key Components:**
- Flask application setup
- Authentication system (Flask-Login)
- Encryption functions
- Route handlers
- Security utilities

---

### 9. Production Considerations (13:00 - 14:00)
**Visual**: Show security recommendations

**Narration:**
"Before we wrap up, let me mention some important considerations for production deployment:"

**Recommendations:**
1. **Use HTTPS**: Always use TLS/SSL in production
2. **Key Management**: Use a proper key management service
3. **Database**: Replace in-memory user storage with a database
4. **Rate Limiting**: Implement rate limiting on authentication endpoints
5. **CSRF Protection**: Add CSRF tokens to forms
6. **Security Headers**: Implement security headers (CSP, HSTS, etc.)
7. **Logging**: Add comprehensive logging and monitoring
8. **Error Handling**: Disable debug mode and use generic error messages

**Narration:**
"These improvements will enhance the security posture of the application for production use."

---

### 10. Conclusion (14:00 - 15:00)
**Visual**: Application dashboard

**Narration:**
"In this walkthrough, we've explored the Flask Secure File Portal and its encryption implementation. We've seen how files are encrypted using AES-256 before storage, how the encryption key is managed, and how files are decrypted on demand.

The application demonstrates strong security practices including password hashing, path validation, and robust file encryption. The AES-256 encryption ensures that files are protected at rest and cannot be read without the encryption key.

Thank you for watching! For more information, check out the README and Security Overview documents in the repository."

---

## Visual Elements Checklist

- [ ] Application login screen
- [ ] Dashboard interface
- [ ] File upload process
- [ ] Code snippets highlighting key functions
- [ ] File system showing encrypted files
- [ ] Keys directory structure
- [ ] Download process
- [ ] Decrypted file verification
- [ ] Security features demonstration
- [ ] Architecture diagram (optional)

---

## Key Talking Points

1. **AES-256 Encryption**: Industry-standard, strong encryption
2. **CBC Mode**: Provides security through chaining and unique IVs
3. **Key Management**: Current implementation vs. production recommendations
4. **Security Layers**: Multiple security measures working together
5. **File Format**: IV + encrypted data structure
6. **Path Security**: Directory traversal prevention
7. **Authentication**: Session-based access control

---

## Tips for Recording

1. **Code Highlighting**: Use syntax highlighting when showing code
2. **Slow Pacing**: Explain encryption concepts clearly and slowly
3. **Visual Aids**: Show file system changes when files are encrypted
4. **Error Demonstration**: Show what happens with invalid inputs (optional)
5. **Comparison**: Show encrypted vs. decrypted file sizes (optional)

---

## Additional Segments (Optional)

### A. Error Handling Demonstration
- Show invalid filename handling
- Demonstrate path traversal prevention
- Show authentication redirects

### B. Performance Discussion
- Encryption speed
- File size overhead
- Memory usage

### C. Comparison with Other Methods
- Why AES-256 over other algorithms
- Why CBC mode
- Why this key management approach

---

**Script Version**: 1.0  
**Estimated Duration**: 10-15 minutes  
**Target Audience**: Technical (Developers, Security Professionals)

