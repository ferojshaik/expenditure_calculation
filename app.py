from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pdfplumber
import re
from decimal import Decimal
import os
from datetime import timedelta, datetime
import secrets
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from flask_talisman import Talisman
from collections import defaultdict
from flask_wtf import FlaskForm
import logging
from logging.handlers import RotatingFileHandler
from sqlalchemy import create_engine
from sqlalchemy_utils import database_exists, create_database

app = Flask(__name__)
# Use environment variable for secret key
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///users.db')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)  # Session expires after 30 minutes
app.config['SESSION_PROTECTION'] = 'strong'
app.config['REMEMBER_COOKIE_SECURE'] = True  # Only send cookies over HTTPS
app.config['REMEMBER_COOKIE_HTTPONLY'] = True  # Prevent JavaScript access to cookies
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

csrf = CSRFProtect(app)

Talisman(app, 
    content_security_policy={
        'default-src': "'self'",
        'style-src': ["'self'", "'unsafe-inline'", "fonts.googleapis.com"],
        'font-src': ["'self'", "fonts.gstatic.com"],
    },
    force_https=True
)

# Disable HTTPS requirement in development
if os.environ.get('FLASK_ENV') != 'production':
    app.config['SESSION_COOKIE_SECURE'] = False
    app.config['REMEMBER_COOKIE_SECURE'] = False

# User Model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.DateTime)
    account_locked_until = db.Column(db.DateTime)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def is_account_locked(self):
        if self.account_locked_until and self.account_locked_until > datetime.utcnow():
            return True
        return False

# Transaction History Model
class TransactionHistory(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    description = db.Column(db.String(200))
    amount = db.Column(db.Float)
    type = db.Column(db.String(10))  # 'debit' or 'credit'
    date = db.Column(db.DateTime, default=db.func.current_timestamp())

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def extract_transactions_from_pdf(pdf_file):
    transactions = []
    
    try:
        with pdfplumber.open(pdf_file) as pdf:
            print(f"Successfully opened PDF with {len(pdf.pages)} pages")
            
            for page_num, page in enumerate(pdf.pages):
                print(f"\nProcessing page {page_num + 1}")
                text = page.extract_text()
                
                lines = text.split('\n')
                for line in lines:
                    # Look for DEBIT transactions
                    if ('Paid to' in line or 'Payment to' in line) and 'DEBIT' in line:
                        amount_match = re.search(r'DEBIT\s*₹\s*([\d,]+\.?\d*)', line)
                        if amount_match:
                            amount_str = amount_match.group(1).replace(',', '')
                            try:
                                amount = Decimal(amount_str)
                                description = line.split('DEBIT')[0].strip()
                                transaction = {
                                    'amount': amount,
                                    'description': description,
                                    'type': 'debit'
                                }
                                transactions.append(transaction)
                            except Exception as e:
                                print(f"Error converting debit amount '{amount_str}': {str(e)}")
                                continue
                    
                    # Look for CREDIT transactions
                    elif 'CREDIT' in line:
                        amount_match = re.search(r'CREDIT\s*₹\s*([\d,]+\.?\d*)', line)
                        if amount_match:
                            amount_str = amount_match.group(1).replace(',', '')
                            try:
                                amount = Decimal(amount_str)
                                description = line.split('CREDIT')[0].strip()
                                transaction = {
                                    'amount': amount,
                                    'description': description,
                                    'type': 'credit'
                                }
                                transactions.append(transaction)
                            except Exception as e:
                                print(f"Error converting credit amount '{amount_str}': {str(e)}")
                                continue
    
    except Exception as e:
        print(f"Error processing PDF: {str(e)}")
        return []
    
    total_debit = sum(t['amount'] for t in transactions if t['type'] == 'debit')
    total_credit = sum(t['amount'] for t in transactions if t['type'] == 'credit')
    print(f"\nTotal transactions found: {len(transactions)}")
    print(f"Total debit: ₹{total_debit}")
    print(f"Total credit: ₹{total_credit}")
    
    return transactions

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = FlaskForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST' and form.validate():
        username = request.form['username']
        password = request.form['password']
        
        # Check username length
        if len(username) < 4:
            flash('Username must be at least 4 characters long')
            return redirect(url_for('register'))
            
        # Check password strength
        if not is_password_strong(password):
            flash('Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters')
            return redirect(url_for('register'))
        
        # Check if username exists
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        # Add rate limiting for registration attempts
        if not check_rate_limit(request.remote_addr, 'register'):
            flash('Too many registration attempts. Please try again later.')
            return redirect(url_for('register'))
        
        user = User(username=username)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful')
        return redirect(url_for('login'))
    
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = FlaskForm()
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
        
    if request.method == 'POST' and form.validate():
        username = request.form['username']
        password = request.form['password']
        
        # Add rate limiting for failed login attempts
        if not check_rate_limit(request.remote_addr, 'login_fail'):
            flash('Too many failed attempts. Please try again later.')
            return redirect(url_for('login'))
            
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            reset_rate_limit(request.remote_addr, 'login_fail')
            return redirect(url_for('dashboard'))
        else:
            increment_rate_limit(request.remote_addr, 'login_fail')
            flash('Invalid username or password')
    
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out successfully')
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    # Get sort parameter from URL (?sort=asc, ?sort=desc, or default)
    sort = request.args.get('sort', 'default')
    
    # Get base query
    transactions = TransactionHistory.query.filter_by(user_id=current_user.id)
    
    # Apply sorting
    if sort == 'asc':
        transactions = transactions.order_by(TransactionHistory.amount.asc())
    elif sort == 'desc':
        transactions = transactions.order_by(TransactionHistory.amount.desc())
    else:
        transactions = transactions.order_by(TransactionHistory.date.desc())
    
    transactions = transactions.all()
    
    total_debit = sum(t.amount for t in transactions if t.type == 'debit')
    total_credit = sum(t.amount for t in transactions if t.type == 'credit')
    
    return render_template('dashboard.html', 
                         transactions=transactions, 
                         total_debit=total_debit,
                         total_credit=total_credit,
                         current_sort=sort)

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    form = FlaskForm()
    if request.method == 'POST':
        if not form.validate():
            flash('Form validation failed')
            return redirect(request.url)
            
        if 'file' not in request.files:
            flash('No file uploaded')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No file selected')
            return redirect(request.url)
        
        if file and file.filename.endswith('.pdf'):
            try:
                # Clear existing transactions for this user
                TransactionHistory.query.filter_by(user_id=current_user.id).delete()
                db.session.commit()
                
                file_path = "temp.pdf"
                file.save(file_path)
                
                with open(file_path, 'rb') as f:
                    transactions = extract_transactions_from_pdf(f)
                
                # Save new transactions to database
                for trans in transactions:
                    new_transaction = TransactionHistory(
                        user_id=current_user.id,
                        description=trans['description'],
                        amount=float(trans['amount']),
                        type=trans['type']
                    )
                    db.session.add(new_transaction)
                db.session.commit()
                
                flash('Transactions updated successfully')
                return redirect(url_for('dashboard'))
            except Exception as e:
                flash(f"Error processing PDF: {str(e)}")
                return redirect(request.url)
            finally:
                if os.path.exists("temp.pdf"):
                    os.remove("temp.pdf")
    
    return render_template('upload.html', form=form)

# Add password complexity requirements
def is_password_strong(password):
    if len(password) < 8:
        return False
    if not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[a-z]", password):
        return False
    if not re.search(r"[0-9]", password):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
        return False
    return True

# Rate limiting helper functions
rate_limits = defaultdict(lambda: {'count': 0, 'reset_time': datetime.utcnow()})

def check_rate_limit(ip, action, max_attempts=5, window=300):  # 5 attempts per 5 minutes
    key = f"{ip}:{action}"
    now = datetime.utcnow()
    
    # Reset counter if time window has passed
    if (now - rate_limits[key]['reset_time']).seconds > window:
        rate_limits[key] = {'count': 0, 'reset_time': now}
    
    return rate_limits[key]['count'] < max_attempts

def increment_rate_limit(ip, action):
    key = f"{ip}:{action}"
    rate_limits[key]['count'] += 1

def reset_rate_limit(ip, action):
    key = f"{ip}:{action}"
    rate_limits[key] = {'count': 0, 'reset_time': datetime.utcnow()}

# Database configuration
if os.environ.get('FLASK_ENV') == 'production':
    # Use PostgreSQL in production
    db_url = os.environ.get('DATABASE_URL')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
else:
    # Use SQLite in development
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'

if os.environ.get('FLASK_ENV') == 'production':
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
    ))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Application startup')

def init_db():
    try:
        db_url = os.environ.get('DATABASE_URL')
        if db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        
        engine = create_engine(db_url)
        if not database_exists(engine.url):
            create_database(engine.url)
        
        db.create_all()
        print("Database initialized successfully")
    except Exception as e:
        print(f"Error initializing database: {str(e)}")

if __name__ == '__main__':
    with app.app_context():
        init_db()  # Initialize database tables
    app.run(debug=True) 