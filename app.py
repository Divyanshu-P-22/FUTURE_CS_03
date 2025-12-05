import os
import secrets
from io import BytesIO
from flask import Flask, render_template, request, redirect, url_for, flash, send_file, abort
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# --- Configuration ---
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16 MB limit
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'protected_files')
KEY_FOLDER = os.path.join(BASE_DIR, 'keys')
KEY_FILE = os.path.join(KEY_FOLDER, 'encryption.key')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'xlsx', 'zip'}

# Ensure directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(KEY_FOLDER, exist_ok=True)

# --- Key Management ---
def load_or_create_key():
    if os.path.exists(KEY_FILE):
        with open(KEY_FILE, 'rb') as f:
            return f.read()
    else:
        key = get_random_bytes(32)  # AES-256
        with open(KEY_FILE, 'wb') as f:
            f.write(key)
        return key

ENCRYPTION_KEY = load_or_create_key()

# --- Auth Setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# In-memory user store (Production note: Use a DB in real deployments)
USERS = {
    'admin': generate_password_hash('admin123'),
    'user1': generate_password_hash('password123')
}

class User(UserMixin):
    def __init__(self, id):
        self.id = id

@login_manager.user_loader
def load_user(user_id):
    return User(user_id) if user_id in USERS else None

# --- Helper Functions ---
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def encrypt_data(data: bytes) -> bytes:
    iv = get_random_bytes(16)
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    return iv + ciphertext  # Store IV || Ciphertext

def decrypt_data(encrypted_data: bytes) -> bytes:
    iv = encrypted_data[:16]
    ciphertext = encrypted_data[16:]
    cipher = AES.new(ENCRYPTION_KEY, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ciphertext), AES.block_size)

# --- Routes ---
@app.route('/')
def index():
    return redirect(url_for('dashboard'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        if username in USERS and check_password_hash(USERS[username], password):
            login_user(User(username))
            return redirect(url_for('dashboard'))
        flash('Invalid credentials.', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    files = []
    try:
        # List only .enc files
        for f in os.listdir(UPLOAD_FOLDER):
            if f.endswith('.enc'):
                original_name = f[:-4] # Remove .enc
                size = os.path.getsize(os.path.join(UPLOAD_FOLDER, f))
                files.append({'name': original_name, 'size': size, 'stored_name': f})
    except OSError:
        flash('Error reading file storage.', 'danger')
    return render_template('dashboard.html', files=files)

@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file part.', 'warning')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    if file.filename == '':
        flash('No selected file.', 'warning')
        return redirect(url_for('dashboard'))

    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        try:
            file_data = file.read()
            encrypted_content = encrypt_data(file_data)
            
            save_path = os.path.join(UPLOAD_FOLDER, f"{filename}.enc")
            with open(save_path, 'wb') as f:
                f.write(encrypted_content)
            
            flash(f'File "{filename}" encrypted and uploaded.', 'success')
        except Exception as e:
            flash(f'Encryption failed: {str(e)}', 'danger')
    else:
        flash('Invalid file type or extension.', 'danger')
        
    return redirect(url_for('dashboard'))

@app.route('/download/<path:filename>')
@login_required
def download_file(filename):
    # Security: Ensure filename is safe and exists
    safe_name = secure_filename(filename)
    file_path = os.path.join(UPLOAD_FOLDER, f"{safe_name}.enc")
    
    if not os.path.exists(file_path):
        abort(404)

    try:
        with open(file_path, 'rb') as f:
            encrypted_data = f.read()
            
        decrypted_data = decrypt_data(encrypted_data)
        
        return send_file(
            BytesIO(decrypted_data),
            download_name=safe_name,
            as_attachment=True
        )
    except ValueError:
        flash('Decryption failed. Key mismatch or corrupted file.', 'danger')
        return redirect(url_for('dashboard'))
    except Exception as e:
        flash(f'System error: {str(e)}', 'danger')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    # Debug is explicitly disabled for production context readiness
    app.run(host='0.0.0.0', port=5000, debug=False)