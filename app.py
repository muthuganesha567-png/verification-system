from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import os
import uuid
import hashlib
import json
import time
import smtplib
import random
import string
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from datetime import datetime, timedelta
from PyPDF2 import PdfReader

# ---------------- Blockchain Class ----------------
class Blockchain:
    def __init__(self):
        self.chain = []
        self.current_transactions = []
        self.new_block(proof=100, previous_hash='1')

    def new_block(self, proof, previous_hash=None):
        """
        Create a new Block in the Blockchain
        :param proof: The proof given by the Proof of Work algorithm
        :param previous_hash: Hash of previous Block
        :return: New Block
        """
        if previous_hash is None:
            previous_hash = self.hash(self.chain[-1]) if self.chain else '1'

        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': self.current_transactions.copy(),
            'proof': proof,
            'previous_hash': previous_hash,
        }
        self.current_transactions = []
        self.chain.append(block)
        return block

    def new_transaction(self, college_code, document_name, file_hash):
        """
        Creates a new transaction to go into the next mined Block
        :param college_code: College's unique code
        :param document_name: Name of the document (e.g., "Degree Certificate")
        :param file_hash: SHA-256 hash of the document file
        :return: The index of the Block that will hold this transaction
        """
        self.current_transactions.append({
            'college_code': college_code,
            'document_name': document_name,
            'file_hash': file_hash,
        })
        return self.last_block['index'] + 1

    @property
    def last_block(self):
        return self.chain[-1]

    @staticmethod
    def hash(block):
        """
        Creates a SHA-256 hash of a Block
        :param block: Block
        :return: Hash string
        """
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    def proof_of_work(self, last_proof):
        """
        Simple Proof of Work Algorithm:
         - Find a number 'p' such that hash(last_proof, p) contains 4 leading zeroes
         - 'last_proof' is the proof of the previous block
         - 'p' is the current proof
        :param last_proof: <int>
        :return: <int>
        """
        proof = 0
        while not self.valid_proof(last_proof, proof):
            proof += 1
        return proof

    @staticmethod
    def valid_proof(last_proof, proof):
        """
        Validates the Proof: Does hash(last_proof, proof) contain 4 leading zeroes?
        :param last_proof: <int> Previous Proof
        :param proof: <int> Current Proof
        :return: <bool> True if correct, False otherwise.
        """
        guess = f'{last_proof}{proof}'.encode()
        guess_hash = hashlib.sha256(guess).hexdigest()
        return guess_hash[:4] == "0000"

    def validate_chain(self, chain):
        """
        Determines if a given blockchain is valid
        :param chain: <list> A blockchain
        :return: <bool> True if valid, False if not
        """
        last_block = chain[0]
        current_index = 1

        while current_index < len(chain):
            block = chain[current_index]
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self.valid_proof(last_block['proof'], block['proof']):
                return False
            last_block = block
            current_index += 1

        return True

# ---------------- Initialize Blockchain ----------------
blockchain = Blockchain()

# ---------------- Flask App ----------------
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SECRET_KEY'] = 'replace_this_with_some_random_secret'

DEVELOPER_PASSWORD = "6369269699sarvaa"

# ---------------- Email Configuration ----------------
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_ADDRESS = "only2sarvaa@gmail.com"
EMAIL_PASSWORD = "koih ssdj esfp qyfr"

otp_storage = {}

# ---------------- Custom Filters ----------------
@app.template_filter('ctime')
def timectime(s):
    from time import ctime
    try:
        return ctime(s)
    except Exception:
        return str(s)

# ---------------- Database Setup ----------------
def init_db():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS certificates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    college_code TEXT,
                    college_name TEXT,
                    address TEXT,
                    degree TEXT,
                    year TEXT,
                    department TEXT,
                    document_name TEXT,
                    filename TEXT,
                    file_hash TEXT
                )''')
    c.execute('''CREATE TABLE IF NOT EXISTS colleges (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    college_name TEXT,
                    address TEXT,
                    unique_code TEXT,
                    student_code TEXT,
                    email TEXT
                )''')
    conn.commit()
    conn.close()

def update_db_schema():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    try:
        c.execute('ALTER TABLE colleges ADD COLUMN email TEXT')
        print("email column added.")
    except sqlite3.OperationalError as e:
        if "duplicate column name" in str(e):
            print("email column already exists.")
        else:
            print("Error updating schema:", e)
    conn.commit()
    conn.close()

init_db()
update_db_schema()

# ---------------- Helper Functions ----------------
def calculate_file_hash(filepath):
    sha256 = hashlib.sha256()

    if filepath.lower().endswith(".pdf"):
        try:
            reader = PdfReader(filepath)
            text_content = ""
            for page in reader.pages:
                text_content += page.extract_text() or ""
            sha256.update(text_content.encode("utf-8"))
            return sha256.hexdigest()
        except Exception as e:
            print("PDF parsing failed, falling back to raw hash:", e)

    with open(filepath, "rb") as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            sha256.update(chunk)
    return sha256.hexdigest()

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def send_otp_email(college_email, otp):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = college_email
        msg['Subject'] = "Your OTP for Admin Portal Access"
        
        body = f"""
        <h2>Certificate Verification System</h2>
        <p>Your OTP for admin portal access is: <strong>{otp}</strong></p>
        <p>This OTP is valid for 10 minutes.</p>
        <p>If you didn't request this OTP, please ignore this email.</p>
        """
        
        msg.attach(MIMEText(body, 'html'))
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def send_certificate_email(college_email, college_name, documents):
    try:
        msg = MIMEMultipart()
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = college_email
        msg['Subject'] = f"Certificates Uploaded Successfully - {college_name}"
        
        body = f"""
        <h2>Certificate Verification System</h2>
        <p>Your certificates have been successfully uploaded to the blockchain.</p>
        <p><strong>College:</strong> {college_name}</p>
        <p><strong>Upload Time:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Uploaded Documents:</strong></p>
        <ul>
        """
        
        for doc in documents:
            body += f"<li>{doc.filename}</li>"
        
        body += "</ul><p>These certificates are now securely stored on the blockchain and can be verified by anyone.</p>"
        
        msg.attach(MIMEText(body, 'html'))
        
        for doc in documents:
            doc.seek(0)
            part = MIMEApplication(doc.read(), Name=doc.filename)
            part['Content-Disposition'] = f'attachment; filename="{doc.filename}"'
            msg.attach(part)
        
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Error sending certificate email: {e}")
        return False

# ---------------- Routes ----------------
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/developer', methods=['GET', 'POST'])
def developer():
    if request.method == 'POST':
        pwd = request.form.get('password', '')
        if pwd == DEVELOPER_PASSWORD:
            session['dev_logged_in'] = True
            return redirect(url_for('dev_dashboard'))
        else:
            flash("Wrong developer password.", "error")
            return redirect(url_for('developer'))
    return render_template('developer.html')

@app.route('/dev/dashboard', methods=['GET', 'POST'])
def dev_dashboard():
    if not session.get('dev_logged_in'):
        return redirect(url_for('developer'))

    if request.method == 'POST':
        college_name = request.form.get('college_name')
        address = request.form.get('address')
        email = request.form.get('email')
        unique_code = request.form.get('unique_code')
        student_code = request.form.get('student_code')

        if not (college_name and address and email and unique_code and student_code):
            flash("Please fill all fields.", "error")
            return redirect(url_for('dev_dashboard'))

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('INSERT INTO colleges (college_name, address, unique_code, student_code, email) VALUES (?, ?, ?, ?, ?)',
                  (college_name, address, unique_code, student_code, email))
        conn.commit()
        conn.close()

        flash("College added with codes: " + unique_code + " (admin), " + student_code + " (student)", "success")
        return redirect(url_for('dev_dashboard'))

    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT id, college_name, address, unique_code, student_code FROM colleges ORDER BY id DESC')
    colleges = c.fetchall()
    conn.close()

    return render_template('dev_dashboard.html', colleges=colleges)

@app.route('/dev/logout')
def dev_logout():
    session.pop('dev_logged_in', None)
    return redirect(url_for('index'))

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        college_name = request.form.get('college_name')
        address = request.form.get('address')
        unique_code = request.form.get('unique_code')

        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT id, email FROM colleges WHERE college_name = ? AND address = ? AND unique_code = ?',
                  (college_name, address, unique_code))
        res = c.fetchone()
        conn.close()

        if res:
            otp = generate_otp()
            otp_storage[res[0]] = {
                'otp': otp,
                'expires': datetime.now() + timedelta(minutes=10)
            }
            session['college_id'] = res[0]
            session['college_name'] = college_name
            session['college_address'] = address
            session['unique_code'] = unique_code

            if send_otp_email(res[1], otp):
                flash("OTP sent to your registered email.", "success")
                return redirect(url_for('admin_verify_otp'))
            else:
                flash("Failed to send OTP.", "error")
                return redirect(url_for('admin_login'))
        else:
            flash("Invalid details.", "error")
            return redirect(url_for('admin_login'))

    return render_template('admin_login.html')

@app.route('/admin_verify_otp', methods=['GET', 'POST'])
def admin_verify_otp():
    if 'college_id' not in session:
        flash("Session expired.", "error")
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        college_id = session.get('college_id')
        user_otp = request.form.get('otp')

        if college_id in otp_storage:
            stored_otp = otp_storage[college_id]

            if datetime.now() > stored_otp['expires']:
                flash("OTP expired.", "error")
                return redirect(url_for('admin_login'))

            if user_otp == stored_otp['otp']:
                session['admin_authenticated'] = True
                del otp_storage[college_id]
                flash("OTP verified. You can now upload.", "success")
                return redirect(url_for('admin'))
            else:
                flash("Invalid OTP.", "error")
                return redirect(url_for('admin_verify_otp'))
        else:
            flash("Session expired.", "error")
            return redirect(url_for('admin_login'))

    return render_template('admin_verify_otp.html', college_name=session.get('college_name'))

@app.route('/admin', methods=['GET', 'POST'])
def admin():
    if not session.get('admin_authenticated'):
        return redirect(url_for('admin_login'))

    if request.method == 'POST':
        # Retrieve data from form, not session
        college_name = request.form.get('college_name')
        address = request.form.get('address')
        degree = request.form['degree']
        year = request.form['year']
        department = request.form['department']
        documents = request.files.getlist('documents')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT unique_code, email FROM colleges WHERE college_name = ? AND address = ?',
                  (college_name, address))
        row = c.fetchone()
        
        if row:
            college_code = row[0]
            email = row[1]
        else:
            flash("College not found in database. Please register it first.", "error")
            conn.close()
            return redirect(url_for('admin'))

        # Prepare list of documents for email attachment
        uploaded_documents = []
        
        for doc in documents:
            if doc and doc.filename:
                filename = str(uuid.uuid4()) + "_" + doc.filename
                os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
                filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                doc.save(filepath)

                file_hash = calculate_file_hash(filepath)

                c.execute('''INSERT INTO certificates 
                            (college_code, college_name, address, degree, year, department, document_name, filename, file_hash)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)''',
                            (college_code, college_name, address, degree, year, department, doc.filename, filename, file_hash))
                conn.commit()

                blockchain.new_transaction(college_code, doc.filename, file_hash)
                proof = blockchain.proof_of_work(blockchain.last_block['proof'])
                blockchain.new_block(proof)
                
                uploaded_documents.append(doc)

        conn.close()
        
        # Send confirmation email
        send_certificate_email(email, college_name, uploaded_documents)

        flash("Data saved and email sent!", "success")
        return redirect(url_for('admin'))

    pre_college = session.get('college_name', '')
    pre_address = session.get('college_address', '')
    return render_template('admin.html', college_name=pre_college, address=pre_address)

@app.route('/admin_logout')
def admin_logout():
    session.pop('admin_authenticated', None)
    session.pop('college_id', None)
    session.pop('college_name', None)
    session.pop('college_address', None)
    session.pop('unique_code', None)
    return redirect(url_for('index'))

@app.route('/user', methods=['GET', 'POST'])
def user():
    if request.method == 'POST':
        student_code = request.form['student_code']
        college_name = request.form['college_name']
        address = request.form['address']
        degree = request.form['degree']
        department = request.form['department']
        documents = request.files.getlist('documents')
        
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT unique_code FROM colleges WHERE college_name = ? AND address = ? AND student_code = ?',
                  (college_name, address, student_code))
        college = c.fetchone()
        
        if not college:
            conn.close()
            return render_template('user.html', results=["❌ Invalid student code for this college"])

        college_code = college[0]
        results = []
        verified_any = False
        
        for doc in documents:
            if doc and doc.filename:
                # To calculate hash, the file object needs to be read from the beginning
                doc.seek(0)
                file_bytes = doc.read()
                file_hash = hashlib.sha256(file_bytes).hexdigest()

                c.execute('''SELECT * FROM certificates 
                            WHERE college_code = ? AND college_name = ? AND address = ? 
                            AND degree = ? AND department = ? AND file_hash = ?''',
                            (college_code, college_name, address, degree, department, file_hash))
                result = c.fetchone()
                
                if result:
                    results.append(f"✅ Verified: {doc.filename}")
                    verified_any = True
                else:
                    results.append(f"❌ Not Found / Tampered: {doc.filename}")

        conn.close()
        
        if verified_any:
            return redirect(url_for('success'))
        else:
            return render_template('verification_failed.html', results=results)

    return render_template('user.html')

@app.route('/history', methods=['GET', 'POST'])
def history():
    if request.method == 'POST':
        college_code = request.form['college_code']
        conn = sqlite3.connect('database.db')
        c = conn.cursor()
        c.execute('SELECT * FROM certificates WHERE college_code = ?', (college_code,))
        records = c.fetchall()
        conn.close()
        return render_template('history.html', records=records, college_code=college_code)

    return render_template('history.html', records=None, college_code=None)

@app.route('/colleges')
def colleges_list():
    conn = sqlite3.connect('database.db')
    c = conn.cursor()
    c.execute('SELECT college_name, address, unique_code, student_code FROM colleges')
    rows = c.fetchall()
    conn.close()
    return {"colleges": rows}

@app.route('/blockchain')
def view_blockchain():
    return render_template('blockchain.html', chain=blockchain.chain)

@app.route('/success')
def success():
    return render_template('success.html')

# ---------------- Run Server ----------------
if __name__ == '__main__':
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    app.run(debug=True, host='127.0.0.1', port=5001)