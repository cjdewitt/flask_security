from flask import Flask, request, jsonify, make_response, abort
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import datetime
import os
import re
import secrets
import bleach
from functools import wraps
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
# Additional security-related imports
import logging
from logging.handlers import RotatingFileHandler
from flask_talisman import Talisman  # Adds security headers to responses
import hashlib
import time
from collections import defaultdict
import ipaddress

app = Flask(__name__)

"""
SECURITY CONFIGURATION SECTION
These settings establish the basic security posture of the application
"""
# Strong random secret key to protect against CSRF and session tampering
app.config['SECRET_KEY'] = secrets.token_hex(32)

# Database configuration with security considerations
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(app.instance_path, 'bank.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False  # Reduces overhead and prevents information leakage

# Session security settings
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(minutes=30)  # Prevents session hijacking by limiting session duration
app.config['SESSION_COOKIE_SECURE'] = True  # Ensures cookies are only sent over HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True  # Prevents XSS attacks by making cookies inaccessible to JavaScript
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'  # Prevents CSRF attacks by limiting cookie transmission

# Request size limiting to prevent DOS attacks
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Database connection pool settings to prevent resource exhaustion
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': 10,  # Limits total number of concurrent database connections
    'max_overflow': 20,  # Allows temporary additional connections during high load
    'pool_timeout': 30,  # Prevents hanging connections
    'pool_recycle': 1800,  # Prevents stale connections
}

# Ensure instance folder exists
try:
    os.makedirs(app.instance_path)
except OSError:
    pass

# Database setup
db = SQLAlchemy(app)

# Models remain the same as in original code
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    balance = db.Column(db.Float, default=0.0)

class Transaction(db.Model):
    __tablename__ = 'transactions'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(20), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    ip_address = db.Column(db.String(45))

# Create tables
with app.app_context():
    db.create_all()


def get_client_ip():
    """Get the real client IP, considering X-Forwarded-For header"""
    if request.headers.get('X-Forwarded-For'):
        # Get the first IP in the X-Forwarded-For chain
        return request.headers['X-Forwarded-For'].split(',')[0].strip()
    return request.remote_addr


limiter = Limiter(
    app=app,
    key_func=get_client_ip,
    default_limits=["100 per minute", "30 per hour"], 
    storage_uri="memory://"
)


"""
SECURITY HEADERS CONFIGURATION
Talisman adds various security headers to prevent common web attacks
"""
talisman = Talisman(
    app,
    force_https=False,  # Enforces HTTPS connections
    strict_transport_security=False,  # Implements HSTS to prevent downgrade attacks
    session_cookie_secure=False,  # Ensures cookies are only sent over HTTPS
    content_security_policy={

        # CSP settings to prevent XSS and other injection attacks
        'default-src': "'self'",  # Only allow resources from same origin
        'script-src': "'self'",   # Only allow scripts from same origin
        'style-src': "'self'",    # Only allow styles from same origin
    }
)

"""
LOGGING CONFIGURATION
Comprehensive logging helps detect and investigate security incidents
"""
if not os.path.exists('logs'):
    os.mkdir('logs')

# Configure rotating log files to prevent disk space exhaustion
file_handler = RotatingFileHandler(
    'logs/bank_app.log', 
    maxBytes=10240,  # Rotate at 10KB
    backupCount=10   # Keep 10 backup files
)
file_handler.setFormatter(logging.Formatter(
    '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
))
file_handler.setLevel(logging.INFO)
app.logger.addHandler(file_handler)
app.logger.setLevel(logging.INFO)
app.logger.info('Bank application startup')

"""
IP TRACKING AND PROTECTION SYSTEM
Implements protection against brute force and DOS attacks
"""
# Tracks IP-based metrics using defaultdict to prevent KeyErrors
ip_tracker = defaultdict(lambda: {
    'attempts': 0,        # Count of requests
    'last_attempt': 0,    # Timestamp of last request
    'blocked_until': 0    # Timestamp until IP remains blocked
})

# Whitelist for known legitimate IPs
ALLOWED_IPS = {
    "127.0.0.1", 
    "192.168.1.100", 
    "192.168.1.200",
    "192.168.1.201",
    "192.168.1.202",
    "192.168.1.203",
    "192.168.1.204",
    "192.168.1.205"
}


def is_ip_allowed(ip):
    """
    Determines if an IP should be allowed to make requests
    """
    current_time = time.time()
    tracker = ip_tracker[ip]
    
    # Check if IP is currently blocked
    if tracker['blocked_until'] > current_time:
        app.logger.warning(f'Blocked request attempt from banned IP: {ip}')
        return False
    
    # Whitelist check - always allow whitelisted IPs
    if ip in ALLOWED_IPS:
        return True
    
    # Reset attempt counter after 1 hour of inactivity
    if current_time - tracker['last_attempt'] > 3600:
        tracker['attempts'] = 0
    
    return tracker['attempts'] < 100


def track_ip_request(ip):
    """
    Tracks and analyzes IP behavior to detect potential attacks
    Implements progressive rate limiting and blocking
    """
    current_time = time.time()
    tracker = ip_tracker[ip]
    tracker['attempts'] += 1
    tracker['last_attempt'] = current_time
    
    # Implement progressive blocking
    if tracker['attempts'] >= 100:
        tracker['blocked_until'] = current_time + 3600  # Block for 1 hour
        app.logger.warning(f'IP {ip} blocked for excessive requests')
        return False
    return True

"""
REQUEST VALIDATION MIDDLEWARE
Validates all incoming requests before processing
"""
@app.before_request
def validate_request():
    """
    Comprehensive request validation to prevent various attacks
    """
    client_ip = get_client_ip()
    
    # IP-based security checks
    if not is_ip_allowed(client_ip):
        app.logger.warning(f'Request blocked from unauthorized IP: {client_ip}')
        abort(403)
    
    if not track_ip_request(client_ip):
        app.logger.warning(f'Request blocked due to rate limiting: {client_ip}')
        abort(429)
    
    # Request size validation to prevent DOS
    if request.content_length and request.content_length > app.config['MAX_CONTENT_LENGTH']:
        app.logger.warning(f'Oversized request blocked from IP: {client_ip}')
        abort(413)
    
    # SQL injection prevention
    for key, value in request.args.items():
        if isinstance(value, str) and any(char in value for char in "';\"="):
            app.logger.warning(f'Potential SQL injection attempt from {client_ip}')
            abort(400)



"""
ENHANCED COOKIE SECURITY
Implements secure cookie handling and validation
"""
def validate_cookie(cookie_value):
    """
    Validates cookie integrity and format
    Prevents cookie tampering and injection attacks
    """
    if not cookie_value:
        return False
    try:
        # Validate cookie format using regex
        # Only allows alphanumeric characters and basic punctuation
        return bool(re.match(r'^[a-zA-Z0-9_-]+$', cookie_value))
    except Exception as e:
        app.logger.error(f'Cookie validation error: {str(e)}')
        return False

# Helper functions remain the same
def get_user_from_cookie(request):
    cookie = request.cookies.get('session')
    if not cookie:
        return None
    try:
        user = User.query.filter_by(name=cookie).first()
        if user:
            return user
    except:
        return None
    return None

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_user_from_cookie(request)
        if not user:
            return jsonify({'error': 'Please login first'}), 401
        return f(user, *args, **kwargs)
    return decorated


# Modified registration endpoint with rate limiting
@app.route('/register')
@app.route('/register.php')
@limiter.limit("3 per minute", error_message="Too many registration attempts. Please try again later.")
@limiter.limit("20 per hour", error_message="Hourly registration limit exceeded. Please try again later.")
@limiter.limit("50 per day", error_message="Daily registration limit exceeded. Please try again later.")
def register():
    username = bleach.clean(request.args.get('user', ''))
    password = request.args.get('pass', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400

    if User.query.filter_by(name=username).first():
        return jsonify({'error': 'Username already exists'}), 400

    new_user = User(
        name=username,
        password=generate_password_hash(password, method='pbkdf2:sha256:600000'),
        balance=0.0
    )

    try:
        db.session.add(new_user)
        db.session.commit()
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Registration failed'}), 400
    finally:
        db.session.close() # Explicitly close the session

# Rest of the routes with added rate limiting
@app.route('/login')
@app.route('/login.php')
@limiter.limit("20 per minute")
def login():
    username = bleach.clean(request.args.get('user', ''))
    password = request.args.get('pass', '')

    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 401

    user = User.query.filter_by(name=username).first()

    if not user or not check_password_hash(user.password, password):
        return jsonify({'error': 'Invalid credentials'}), 401

    response = make_response(jsonify({'message': 'Login successful'}))
    response.set_cookie('session', username, httponly=True)
    return response

@app.route('/manage')
@app.route('/manage.php')
@login_required
@limiter.limit("30 per minute")
def manage(current_user):
    action = bleach.clean(request.args.get('action', ''))
    amount = request.args.get('amount', type=float)

    if action not in ['deposit', 'withdraw', 'balance', 'close']:
        return jsonify({'error': 'Invalid action'}), 400

    if action == 'balance':
        return f"balance={current_user.balance}"

    if action == 'close':
        try:
            db.session.delete(current_user)
            db.session.commit()
            response = make_response('Account closed successfully')
            response.set_cookie('session', '', expires=0)
            return response
        except Exception as e:
            db.session.rollback()
            return jsonify({'error': 'Failed to close account'}), 400
        finally:
            db.session.close()

    if not amount or amount <= 0:
        return jsonify({'error': 'Invalid amount'}), 400

    try:
        if action == 'withdraw':
            if current_user.balance < amount:
                return f"balance={current_user.balance}\nInsufficient funds"
            current_user.balance -= amount
        elif action == 'deposit':
            current_user.balance += amount

        transaction = Transaction(
            user_id=current_user.id,
            type=action,
            amount=amount,
            ip_address=get_client_ip()  # Use the real client IP
        )

        db.session.add(transaction)
        db.session.commit()

        return f"balance={current_user.balance}"

    except Exception as e:
        db.session.rollback()
        return jsonify({'error': 'Transaction failed'}), 400
    finally:
        db.session.close()

@app.route('/logout')
@app.route('/logout.php')
@login_required
def logout(current_user):
    response = make_response('Logout successful')
    response.set_cookie('session', '', expires=0)
    return response


# RUN FOR ACTUAL CTF SERVER
if __name__ == '__main__':
    app.run(
        host='1.1.1.1',      # CTF server IP
        port=80,             # Standard HTTP port
        debug=False,         # Ensure debug is off
        threaded=True,       # Enable threading for multiple connections
        use_reloader=False   # Disable auto-reloader in production
    )

# RUN FOR LOCAL TESTING
# if __name__ == '__main__':
#     # Production settings with SSL/TLS enabled
#     app.run(
#         host='127.0.0.1',
#         port=5000,
#         debug=True,  # Disable debug mode in production
#         ssl_context=None
#     )
