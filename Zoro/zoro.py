# Imports
import os
import sqlite3
import hashlib
import secrets
from datetime import datetime
from functools import wraps
from flask import Flask, render_template, request, session, redirect, url_for, flash, g, send_file
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from blockchain.ipfs_client import IPFSClient
from blockchain.local_blockchain import HyperledgerClient
# Flask app and config
app = Flask(__name__)
app.secret_key = secrets.token_hex(16)
DATABASE_PATH = 'database/users.db'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
# Generate encryption key
def generate_key():
    if not os.path.exists('database/key.key'):
        os.makedirs('database', exist_ok=True)
        key = Fernet.generate_key()
        with open('database/key.key', 'wb') as key_file:
            key_file.write(key)
    else:
        with open('database/key.key', 'rb') as key_file:
            key = key_file.read()
    return key

ENCRYPTION_KEY = generate_key()
cipher_suite = Fernet(ENCRYPTION_KEY)
# Initialize database schema
def init_db():
    if not os.path.exists(DATABASE_PATH):
        os.makedirs(os.path.dirname(DATABASE_PATH), exist_ok=True)
        conn = sqlite3.connect(DATABASE_PATH)
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                role TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                filename TEXT NOT NULL,
                ipfs_hash TEXT NOT NULL,
                uploaded_by TEXT NOT NULL,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                encrypted_key TEXT NOT NULL
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS audit_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                action TEXT NOT NULL,
                username TEXT NOT NULL,
                filename TEXT NOT NULL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                blockchain_tx TEXT NOT NULL
            )
        ''')
        admin_pass = hashlib.sha256('adminpassword'.encode()).hexdigest()
        user1_pass = hashlib.sha256('user1password'.encode()).hexdigest()
        
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('admin', admin_pass, 'admin'))
        c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", 
                  ('user1', user1_pass, 'user'))
        
        conn.commit()
        conn.close()
init_db()
# Database connection per request
def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE_PATH)
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
# Close DB connection after request
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function
# Admin access required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'role' not in session or session['role'] != 'admin':
            flash('Admin access required', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function
# Initialize blockchain and IPFS clients
hyperledger_client = HyperledgerClient()
ipfs_client = IPFSClient(
    host='127.0.0.1',
    port=5001,
    encryption_key=ENCRYPTION_KEY
)
# Root route
@app.route('/')
def index():
    return redirect(url_for('login'))

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    """
    Handle user login. 
    GET: Display login form
    POST: Process login form submission
    """
    if request.method == 'POST':
        username = request.form['username']
        password = hashlib.sha256(request.form['password'].encode()).hexdigest()
        
        conn = get_db()
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ? AND password = ?", (username, password))
        user = c.fetchone()
        
        if user:
            session['username'] = username
            session['role'] = user['role']
            flash(f'Welcome, {username}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    """
    Handle user logout by clearing session data.
    """
    session.pop('username', None)
    session.pop('role', None)
    flash('You have been logged out', 'success')
    return redirect(url_for('login'))

# Blockchain stats route
@app.route('/blockchain/stats')
@login_required
@admin_required
def blockchain_stats():
    """
    Display blockchain statistics for administrators.
    Shows key metrics like block count, transactions, and chain validity.
    """
    stats = hyperledger_client.get_blockchain_stats()
    return render_template('dashboard.html', active_tab='stats', blockchain_stats=stats)

# User dashboard
@app.route('/dashboard')
@login_required
def dashboard():
    """
    Main dashboard view for authenticated users.
    Displays the files tab by default.
    """
    return render_template('dashboard.html', active_tab='files')

# Files listing route
@app.route('/files')
@login_required
def files():
    """
    Display files accessible to the current user.
    Admins can see all files, regular users only see their own uploads.
    """
    conn = get_db()
    c = conn.cursor()
    if session['role'] == 'admin':
        c.execute("SELECT * FROM files ORDER BY upload_date DESC")
    else:
        c.execute("SELECT * FROM files WHERE uploaded_by = ? ORDER BY upload_date DESC", 
                  (session['username'],))
    
    files = c.fetchall()
    return render_template('dashboard.html', active_tab='files', files=files)

# Upload route
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload():
    """
    Handle file uploads with encryption and blockchain logging.
    GET: Display upload form
    POST: Process file upload, encrypt, store on IPFS, and log to blockchain
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{filename}")
            file.save(temp_path)
            with open(temp_path, 'rb') as f:
                file_data = f.read()
            
            encrypted_data = cipher_suite.encrypt(file_data)
            encrypted_path = os.path.join(UPLOAD_FOLDER, filename)
            
            with open(encrypted_path, 'wb') as f:
                f.write(encrypted_data)
            ipfs_hash = ipfs_client.encrypt_and_add_file(encrypted_path)
            conn = get_db()
            c = conn.cursor()
            c.execute(
                "INSERT INTO files (filename, ipfs_hash, uploaded_by, encrypted_key) VALUES (?, ?, ?, ?)",
                (filename, ipfs_hash, session['username'], ENCRYPTION_KEY.decode())
            )
            conn.commit()
            tx_id = hyperledger_client.record_transaction('upload', session['username'], filename)
            c.execute(
                "INSERT INTO audit_logs (action, username, filename, blockchain_tx) VALUES (?, ?, ?, ?)",
                ('upload', session['username'], filename, tx_id)
            )
            conn.commit()
            os.remove(temp_path)
            os.remove(encrypted_path)
            
            flash(f'File {filename} uploaded successfully', 'success')
            return redirect(url_for('files'))
    
    return render_template('dashboard.html', active_tab='upload')

# Download route
@app.route('/download/<int:file_id>')
@login_required
def download(file_id):
    """
    Handle file downloads with blockchain logging.
    Downloads, decrypts, and serves the requested file if user has permission.
    """
    try:
        conn = get_db()
        c = conn.cursor()
        if session['role'] == 'admin':
            c.execute("SELECT * FROM files WHERE id = ?", (file_id,))
        else:
            c.execute("SELECT * FROM files WHERE id = ? AND uploaded_by = ?", 
                    (file_id, session['username']))
        
        file = c.fetchone()
        
        if not file:
            flash('File not found or you do not have permission to download it', 'danger')
            return redirect(url_for('files'))
        filename = file['filename']
        encrypted_path = os.path.join(UPLOAD_FOLDER, f"temp_enc_{filename}")
        decrypted_path = os.path.join(UPLOAD_FOLDER, f"temp_dec_{filename}")
        for path in [encrypted_path, decrypted_path]:
            if os.path.exists(path):
                os.remove(path)
        try:
            if not ipfs_client.get_and_decrypt_file(file['ipfs_hash'], decrypted_path):
                flash('Error retrieving file from IPFS', 'danger')
                return redirect(url_for('files'))
            if os.path.exists(encrypted_path):
                os.remove(encrypted_path)
        except Exception as e:
            flash(f'Error retrieving and decrypting file: {str(e)}', 'danger')
            return redirect(url_for('files'))
        tx_id = hyperledger_client.record_transaction('download', session['username'], filename)
        c.execute(
            "INSERT INTO audit_logs (action, username, filename, blockchain_tx) VALUES (?, ?, ?, ?)",
            ('download', session['username'], filename, tx_id)
        )
        conn.commit()
        def remove_temp_files(response):
            try:
                for path in [encrypted_path, decrypted_path]:
                    if os.path.exists(path):
                        os.remove(path)
            except Exception as e:
                print(f"Error cleaning up temporary files: {e}")
            return response
        
        response = send_file(decrypted_path, as_attachment=True, download_name=filename)
        return remove_temp_files(response)
        
    except FileNotFoundError:
        flash('Error processing the file for download', 'danger')
        return redirect(url_for('files'))
            
    except Exception as e:
        print(f"Download error: {e}")
        flash('An error occurred during the download process', 'danger')
        return redirect(url_for('files'))

# Audit log route
@app.route('/audit')
@login_required
@admin_required
def audit():
    """
    Display audit logs for administrators.
    Combines logs from both the SQLite database and the blockchain.
    """
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC")
    db_logs = c.fetchall()
    blockchain_logs = hyperledger_client.query_all_transactions()
    logs = []
    for log in db_logs:
        logs.append({
            'id': log['id'],
            'action': log['action'],
            'username': log['username'],
            'filename': log['filename'],
            'timestamp': log['timestamp'],
            'blockchain_tx': log['blockchain_tx']
        })
    known_txids = {log['blockchain_tx'] for log in logs}
    for tx in blockchain_logs:
        if 'txid' in tx and tx['txid'] not in known_txids:
            logs.append({
                'id': f"BC-{tx.get('block_index', '0')}",
                'action': tx.get('action', 'unknown'),
                'username': tx.get('username', 'unknown'),
                'filename': tx.get('filename', 'unknown'),
                'timestamp': tx.get('timestamp', datetime.now().isoformat()),
                'blockchain_tx': tx.get('txid', 'unknown')
            })
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    return render_template('dashboard.html', active_tab='audit', logs=logs)

# Application entry point
if __name__ == '__main__':
    try:
        init_db()
        if not os.path.exists(os.path.dirname(hyperledger_client.blockchain.blockchain_file)):
            os.makedirs(os.path.dirname(hyperledger_client.blockchain.blockchain_file), exist_ok=True)
        try:
            ipfs_status = ipfs_client.client.id()
            print("IPFS client connected successfully to:", ipfs_client.api_url)
            print(f"IPFS Node ID: {ipfs_status.get('ID', 'Unknown')}")
        except Exception as ipfs_err:
            print(f"Warning: IPFS connection error: {ipfs_err}")
            print("Application will start, but IPFS operations may fail.")
        blockchain_stats = hyperledger_client.get_blockchain_stats()
        print("Local blockchain initialized at:", hyperledger_client.blockchain.blockchain_file)
        print(f"Blockchain stats: {blockchain_stats['blocks']} blocks, {blockchain_stats['total_transactions']} transactions")
        print("Starting Zoro Blockchain Audit Filing System...")
        app.run(debug=True)
    except Exception as e:
        print(f"Error starting application: {e}")
    finally:
        try:
            ipfs_client.close()
            print("IPFS client closed.")
        except:
            pass
            
        try:
            hyperledger_client.close()
            print("Blockchain client closed.")
        except:
            pass
