[README.md](https://github.com/user-attachments/files/23967129/README.md)
# Secure File Portal – Flask Application

A production-ready demonstration of secure file storage using Python Flask and AES-256 encryption.

## 📋 Feature Summary

  * **Authentication**: Flask-Login implementation with in-memory user storage and PBKDF2/bcrypt password hashing.
  * **AES-256 Encryption**: All uploads are encrypted using PyCryptodome (AES-CBC mode) with a unique 16-byte random IV per file.
  * **Secure Downloads**: On-the-fly decryption in memory (unencrypted files are never stored on disk).
  * **Security Hygiene**: Path traversal protection, strictly allowed file extensions, and HTTP-only session cookies.
  * **Key Persistence**: Automatically generates and persists a 32-byte encryption key on first run.

## 📂 Project Tree

```text
.
├── app.py                  # Main Flask application entry point
├── requirements.txt        # Python dependencies
├── protected_files/        # [Auto-created] Stores encrypted .enc files
├── keys/                   # [Auto-created] Stores encryption.key
├── static/
│   ├── css/style.css       # Custom styling
│   └── js/main.js          # UI logic (flash message dismissal)
├── templates/
│   ├── base.html           # Master layout
│   ├── login.html          # Login form
│   └── dashboard.html      # File list and upload interface
├── README.md               # Project documentation
├── SECURITY_OVERVIEW.md    # Deep dive into crypto implementation
└── LICENSE                 # MIT License
```

## 🚀 Quick Start

1.  **Install Dependencies**

    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the Application**

    ```bash
    python app.py
    ```

    *The server will start on `http://0.0.0.0:5000`*

3.  **Access the Portal**
    Navigate to `http://localhost:5000` in your browser.

## ⚠️ Default Credentials (WARNING)

**Do not use these in a real production environment without changing them.**

| Role | Username | Password |
| :--- | :--- | :--- |
| **Admin** | `admin` | `admin123` |
| **User** | `user1` | `password123` |

## 🔐 Encryption Overview

  * **Algorithm**: AES-256 (Advanced Encryption Standard).
  * **Mode**: CBC (Cipher Block Chaining).
  * **Padding**: PKCS7 (128-bit block size).
  * **Storage**: Files are saved as `<filename>.enc`. The first 16 bytes of the file are the **Initialization Vector (IV)**, followed immediately by the ciphertext.

## ✅ Manual Testing Checklist

Use this checklist to verify the system behaviors:

  - [ ] **Auth Enforcement**: Try accessing `/dashboard` without logging in. You should be redirected to `/login`.
  - [ ] **Upload**: Upload a valid file (e.g., `test.txt`). Verify it appears in the dashboard list.
  - [ ] **Storage Verification**: Check the `protected_files/` folder on your OS. You should see `test.txt.enc`. Try opening it with a text editor; it should be unreadable binary garbage.
  - [ ] **Decryption**: Click "Decrypt & Download" on the dashboard. Verify the downloaded file matches the original exactly.
  - [ ] **Invalid Types**: Try uploading a `.exe` or `.py` file. The system should reject it with an error message.
  - [ ] **Logout**: Click logout and verify the back button does not allow access to the dashboard.

## 🏭 Production Tips

1.  **WSGI Server**: Do not use `python app.py` in production. Use a WSGI server:
    ```bash
    gunicorn -w 4 -b 0.0.0.0:5000 app:app
    ```
2.  **HTTPS**: This application must run behind a reverse proxy (Nginx/Apache) with SSL enabled. Without HTTPS, session cookies and file data are vulnerable in transit.
3.  **Secret Key**: Set the `SECRET_KEY` environment variable to a long random string to ensure session persistence across server restarts.
    ```bash
    export SECRET_KEY='your-super-long-random-string'
    ```
