import os
import re
import logging
from typing import Optional, Dict, Any
from functools import wraps
import random
from datetime import datetime, timedelta
from defusedxml import ElementTree as ET  # Use defusedxml to prevent XXE attacks
import boto3
from botocore.exceptions import ClientError
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, render_template_string, session
import requests
from flask_cors import CORS
from dotenv import load_dotenv
from werkzeug.utils import secure_filename
import base64
from flask import send_from_directory
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman
from aadhaar_ocr import get_ocr_reader
from aadhaar_ocr import validate_and_extract_aadhaar
from document_ocr import validate_and_extract_salary_slip, validate_and_extract_offer_letter, validate_and_extract_qualification_certificate
from smtp import send_email, send_completion_email_to_user, send_completion_email_to_company, send_pf_form_to_company , send_form11_to_company, send_preboarding_confirmation, send_onboarding_confirmation
from models import Base, User, PANVerification, AadhaarVerification, BankVerification, DocumentVerification, VerificationLog , OnboardingData
from pf_form_filler import create_pf_form
from form11_filler import create_form11
load_dotenv()

app = Flask(__name__)

# Require strong secret key from environment (CRITICAL for security)
SECRET_KEY = os.getenv('SECRET_KEY')
if not SECRET_KEY or len(SECRET_KEY) < 32:
    raise ValueError("SECRET_KEY must be set in environment variables and be at least 32 characters long. Generate with: python -c 'import secrets; print(secrets.token_hex(32))'")

app.secret_key = SECRET_KEY

# Configure secure session cookies
app.config['SESSION_COOKIE_SECURE'] = os.getenv('SESSION_COOKIE_SECURE', 'False').lower() == 'true'  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=2)
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max file upload

# CORS Configuration - Restrict to specific origins in production
ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:1000,http://127.0.0.1:1000').split(',')
CORS(app, origins=ALLOWED_ORIGINS, supports_credentials=True)  

# Initialize CSRF Protection
csrf = CSRFProtect(app)

# Disable CSRF for all routes (using session auth + rate limiting instead)
app.config['WTF_CSRF_ENABLED'] = False

# Initialize Rate Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[],  # No default limits - only apply to specific endpoints
    storage_uri="memory://",
    auto_check=False  # Disable automatic rate limiting, only apply to decorated routes
)

# Initialize Security Headers (Talisman)
# Disable in development, enable in production
if os.getenv('FLASK_ENV') == 'production':
    Talisman(app, 
        force_https=True,
        strict_transport_security=True,
        content_security_policy={
            'default-src': "'self'",
            'script-src': ["'self'", "'unsafe-inline'", "cdn.jsdelivr.net"],
            'style-src': ["'self'", "'unsafe-inline'"],
            'img-src': ["'self'", "data:", "https:"],
        },
        content_security_policy_nonce_in=['script-src']
    )  

# Configure logging with file handler and rotation
from logging.handlers import RotatingFileHandler

# Create logs directory if it doesn't exist
logs_dir = os.path.join(os.getcwd(), 'logs')
os.makedirs(logs_dir, exist_ok=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        # File handler with rotation (max 10MB per file, keep 10 backup files)
        RotatingFileHandler(
            os.path.join(logs_dir, 'app.txt'),
            maxBytes=10*1024*1024,  # 10MB
            backupCount=10
        ),
        # Console handler for real-time monitoring
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)
logger.info("="*80)
logger.info("BGV SETU APPLICATION STARTED")
logger.info(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
logger.info("="*80)

# Database Configuration - Use SQLite for local development, PostgreSQL for production
DATABASE_URL = os.getenv('DATABASE_URL')

if not DATABASE_URL:
    logger.warning("[DB] DATABASE_URL not set, using SQLite (bgv_setu.db) for local development")
    DATABASE_URL = 'sqlite:///bgv_setu.db'

# Create SQLAlchemy engine and session
try:
    # SQLite specific configuration
    if DATABASE_URL.startswith('sqlite'):
        engine = create_engine(DATABASE_URL, echo=False, connect_args={'check_same_thread': False})
        logger.info(f"[DB] Using SQLite database: bgv_setu.db")
    else:
        engine = create_engine(DATABASE_URL, echo=False)
        logger.info(f"[DB] Using PostgreSQL database")
    
    db_session = scoped_session(sessionmaker(bind=engine))
    Base.query = db_session.query_property()
    logger.info(f"[DB] Database connection established successfully")
except Exception as e:
    logger.error(f"[DB] Failed to connect to database: {e}")
    raise

# Initialize database tables
def init_db():
    """Initialize database tables"""
    if engine:
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("[DB] Database tables created successfully")
        except Exception as e:
            logger.error(f"[DB] Failed to create tables: {e}")

# Call init_db on startup
init_db()

# Store OTPs temporarily (In production, use Redis or database)
otp_storage = {}

# AWS S3 Configuration
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.getenv('AWS_REGION', 'us-east-1')
S3_BUCKET_NAME = os.getenv('S3_BUCKET_NAME')

# Initialize S3 client
s3_client = None
if AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY and S3_BUCKET_NAME:
    try:
        s3_client = boto3.client(
            's3',
            aws_access_key_id=AWS_ACCESS_KEY_ID,
            aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
            region_name=AWS_REGION
        )
        logger.info("[S3] S3 client initialized successfully")
    except Exception as e:
        logger.error(f"[S3] Failed to initialize S3 client: {e}")
else:
    logger.warning("[S3] S3 credentials not configured, file uploads will be stored locally")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function


REDIRECT_URL = "http://127.0.0.1:1000/digilocker/callback" 

# Load PAN 
PAN_API_URL = os.getenv('PAN_API_URL')
PAN_HEADERS = {
    "x-client-id": os.getenv('PAN_CLIENT_ID'),
    "x-client-secret": os.getenv('PAN_CLIENT_SECRET'),
    "x-product-instance-id": os.getenv('PAN_PRODUCT_INSTANCE_ID'),
    "Content-Type": "application/json"
}

# Load Bank 
BANK_API_URL = os.getenv('BANK_API_URL')
BANK_HEADERS = {
    "x-client-id": os.getenv('BANK_CLIENT_ID'),
    "x-client-secret": os.getenv('BANK_CLIENT_SECRET'),
    "x-product-instance-id": os.getenv('BANK_PRODUCT_INSTANCE_ID'),
    "Content-Type": "application/json"
}

# Load DigiLocker 
DIGILOCKER_BASE_URL = os.getenv('DIGILOCKER_BASE_URL')
DIGILOCKER_HEADERS = {
    "x-client-id": os.getenv('DIGILOCKER_CLIENT_ID'),
    "x-client-secret": os.getenv('DIGILOCKER_CLIENT_SECRET'),
    "x-product-instance-id": os.getenv('DIGILOCKER_PRODUCT_INSTANCE_ID'),
    "Content-Type": "application/json"
}

# Load E-Sign 
ESIGN_API_URL = os.getenv('ESIGN_API_URL')
ESIGN_HEADERS = {
    "x-client-id": os.getenv('ESIGN_CLIENT_ID'),
    "x-client-secret": os.getenv('ESIGN_CLIENT_SECRET'),
    "x-product-instance-id": os.getenv('ESIGN_PRODUCT_INSTANCE_ID'),
    "Content-Type": "application/json"
}


def call_setu_api(url: str, payload: dict, headers: dict) -> dict:
    try:
        logger.debug(f"Calling API {url} with payload: {payload}")
        response = requests.post(url, json=payload, headers=headers, timeout=10)
        logger.info(f"API response status: {response.status_code}")
        logger.info(f"API response body: {response.text}")
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logger.error(f"API request error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"Error response: {e.response.text}")
            try:
                error_data = e.response.json()
                error_message = error_data.get('message', 'External API request failed')
            except:
                error_message = e.response.text or "External API request failed"
            abort(500, description=error_message)
        abort(500, description="External API request failed")


def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def get_verification_status(user_email):
    """Get the current verification status for a user"""
    status = {
        'pan_completed': False,
        'aadhaar_completed': False,
        'documents_completed': False,
        'bank_completed': False
    }
    
    if db_session:
        try:
            # Check PAN verification
            pan = db_session.query(PANVerification).filter_by(user_email=user_email).first()
            status['pan_completed'] = bool(pan)
            
            # Check Aadhaar verification
            aadhaar = db_session.query(AadhaarVerification).filter_by(user_email=user_email).first()
            status['aadhaar_completed'] = bool(aadhaar)
            
            # Check Documents verification
            docs = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
            status['documents_completed'] = bool(docs and docs.qualification_certificate_s3_key)
            
            # Check Bank verification
            bank = db_session.query(BankVerification).filter_by(user_email=user_email).first()
            status['bank_completed'] = bool(bank)
        except Exception as e:
            logger.error(f"[VERIFICATION STATUS] Error checking status: {e}")
    
    return status


def get_next_verification_step(user_email):
    """Get the next verification step user should complete"""
    status = get_verification_status(user_email)
    
    if not status['pan_completed']:
        return 'pan_verification'
    elif not status['aadhaar_completed']:
        return 'aadhaar_verification'
    elif not status['documents_completed']:
        return 'document_verification'
    elif not status['bank_completed']:
        return 'bank_verification'
    else:
        return 'preboarding_page'  # All verifications complete



def send_otp_email(email: str, otp: str):
    """
    Send OTP via email using Brevo REST API
    Fallback to console logging if API key not configured
    """
    print(f"\n{'='*50}")
    print(f"Hi,")
    print(f"")
    print(f"This is your verification code {otp}.")
    print(f"")
    print(f"Thanks")
    print(f"{'='*50}\n")
    return True


@app.route('/generate-otp', methods=['POST'])
@limiter.limit("5 per hour")  # Prevent OTP spam
def generate_otp_route():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    # Whitelist of allowed emails
    ALLOWED_EMAILS = [
        'extra0848@gmail.com',
        'mohdgalib569@gmail.com',
        'user3@example.com',
        'user4@example.com',
        'user5@example.com'
    ]
    
    # Check if email is in whitelist
    if email not in ALLOWED_EMAILS:
        logger.warning(f"[OTP] Unauthorized login attempt from {email}")
        return jsonify({
            'success': False, 
            'error': 'Access denied. Please contact the administrator for access.'
        }), 403
    
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=5)
    
   
    otp_storage[email] = {
        'otp': otp,
        'expiry': expiry,
        'attempts': 0
    }
    
    # Send OTP via email (demo implementation)
    email_sent = send_email(email, otp)

    if email_sent.get('status') == 200:
    
        logger.info(f"[OTP] OTP generated for {email}")
        
        message = 'OTP sent to your email. Valid for 5 minutes.'
        return jsonify({
            'success': True,
            'message': message
        })



@app.route('/verify-otp', methods=['POST'])
@limiter.limit("10 per hour")  # Prevent brute force
def verify_otp_route():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    
    if not email or not otp:
        return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400
  
    if email not in otp_storage:
        return jsonify({'success': False, 'error': 'No OTP generated for this email'}), 400
    
    stored_data = otp_storage[email]
    
   
    if datetime.now() > stored_data['expiry']:
        del otp_storage[email]
        return jsonify({'success': False, 'error': 'OTP has expired. Please generate a new one'}), 400
    
    # Check attempts (max 3 attempts)
    if stored_data['attempts'] >= 3:
        del otp_storage[email]
        return jsonify({'success': False, 'error': 'Maximum attempts exceeded. Please generate a new OTP'}), 400
    
    # Verify OTP
    if stored_data['otp'] == otp:
        
        session['user'] = email
        session['user_name'] = email.split('@')[0].capitalize()
        session['consent_given'] = False
        del otp_storage[email] 
        logger.info(f"[LOGIN] User {email} logged in successfully via OTP")
        
        # Save user to database if not already exists
        if db_session:
            try:
                existing_user = db_session.query(User).filter_by(email=email).first()
                if not existing_user:
                    new_user = User(
                        email=email,
                        name=email.split('@')[0].capitalize()
                    )
                    db_session.add(new_user)
                    db_session.commit()
                    logger.info(f"[DB] New user created: {email}")
                else:
                    # Update last login timestamp
                    existing_user.updated_at = datetime.now()
                    db_session.commit()
                    logger.info(f"[DB] User login timestamp updated: {email}")
            except Exception as db_error:
                db_session.rollback()
                logger.error(f"[DB] Failed to save user: {db_error}")
        
        # Check if there's a pending DigiLocker callback
        if 'pending_digilocker_callback' in session:
            callback_data = session.pop('pending_digilocker_callback')
            logger.info(f"[LOGIN] Processing pending DigiLocker callback after login")
            logger.info(f"[LOGIN] Callback data: {callback_data}")
            
            # Store DigiLocker data in session
            if callback_data.get('success', '').lower() == 'true':
                session['digilocker_request_id'] = callback_data.get('request_id')
                session['digilocker_success'] = True
                
                # Parse scope
                scope = callback_data.get('scope', '')
                if scope:
                    from urllib.parse import unquote
                    scope_decoded = unquote(scope)
                    consented_docs = [doc.strip() for doc in scope_decoded.split('+') if doc.strip()]
                    session['digilocker_scope'] = consented_docs
                    logger.info(f"[LOGIN] Restored DigiLocker session with {len(consented_docs)} documents")
                
                # Skip consent and redirect to aadhaar verification
                session['consent_given'] = True
                session.modified = True
                logger.info(f"[LOGIN] Session restored, redirecting to aadhaar verification")
                return jsonify({'success': True, 'message': 'Login successful', 'redirect': '/aadhaar-verification'})
        
        return jsonify({'success': True, 'message': 'Login successful'})
    else:
        # Incorrect OTP
        stored_data['attempts'] += 1
        remaining = 3 - stored_data['attempts']
        logger.warning(f"[OTP] Failed OTP attempt for {email}. Remaining attempts: {remaining}")
        return jsonify({
            'success': False,
            'error': f'Invalid OTP. {remaining} attempt(s) remaining'
        }), 401


@app.route('/login', methods=['GET'])
def login():
   
    if 'user' in session:
        if session.get('consent_given', False):
            return redirect(url_for('index'))
        else:
            return redirect(url_for('consent'))
    return render_template('login.html')


@app.route('/consent', methods=['GET'])
@login_required
def consent():
    # If consent already given, redirect to index
    if session.get('consent_given', False):
        return redirect(url_for('index'))
    return render_template('consent.html')


@app.route('/submit-consent', methods=['POST'])
@login_required
def submit_consent():
    data = request.json or {}
    signature = data.get('signature', '').strip()
    agreed = data.get('agreed', False)
    
    if not agreed:
        return jsonify({'success': False, 'error': 'You must agree to the terms to continue'}), 400
    
    if not signature or len(signature) < 3:
        return jsonify({'success': False, 'error': 'Please provide your full legal name'}), 400
    
    # Store consent in session
    session['consent_given'] = True
    session['signature'] = signature
    session['consent_timestamp'] = datetime.now().isoformat()
    
    logger.info(f"[CONSENT] User {session['user']} provided consent with signature: {signature}")
    
    return jsonify({'success': True, 'message': 'Consent recorded successfully'})


# Admin preboarding link generation removed - use direct link instead:
# Share this link via email: http://127.0.0.1:1000/preboarding
# Users just need to login and they can access the preboarding directly


@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    session.clear()
    logger.info(f"[LOGOUT] User {username} logged out")
    return redirect(url_for('login'))


@app.route('/preboarding')
@login_required
def preboarding_page():
    """Display preboarding form - accessible directly after login"""
    user_email = session.get('user', 'unknown')
    
    # Check if user has already submitted preboarding
    if db_session:
        existing_preboarding = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
        if existing_preboarding and existing_preboarding.email and existing_preboarding.phone:
            # User has already submitted preboarding
            logger.info(f"[PREBOARDING] User {user_email} already submitted preboarding, redirecting to onboarding")
            return redirect(url_for('onboarding_page'))
    
    # Preboarding is now directly accessible - no verification checks required
    # Users can access via http://127.0.0.1:1000/preboarding after logging in
    
    # Fetch existing verification data
    pan_verification = db_session.query(PANVerification).filter_by(user_email=user_email).first()
    
    # For Aadhaar, prefer DigiLocker verification over manual upload
    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
        user_email=user_email, 
        verification_method='digilocker'
    ).first()
    
    # If no DigiLocker verification, fall back to manual upload
    if not aadhaar_verification:
        aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
            user_email=user_email
        ).first()
    
    bank_verification = db_session.query(BankVerification).filter_by(user_email=user_email).first()
    doc_verification = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
    
    # Prepare pre-filled data
    # Prefer Aadhaar name over PAN name as Aadhaar is the primary identity document
    full_name = ''
    if aadhaar_verification and aadhaar_verification.full_name:
        full_name = aadhaar_verification.full_name
    elif pan_verification and pan_verification.full_name:
        full_name = pan_verification.full_name
    
    # Extract father/husband name from Aadhaar careOf field
    father_name = ''
    if aadhaar_verification and aadhaar_verification.verification_data:
        verification_data = aadhaar_verification.verification_data
        if isinstance(verification_data, dict):
            father_name = verification_data.get('care_of', '')
    
    # Convert DOB format from DD-MM-YYYY to YYYY-MM-DD for HTML date input
    dob = ''
    if aadhaar_verification and aadhaar_verification.date_of_birth:
        dob_raw = aadhaar_verification.date_of_birth
        # Try to parse and convert date format
        try:
            from datetime import datetime
            # Try DD-MM-YYYY format first (DigiLocker format)
            if '-' in dob_raw:
                parts = dob_raw.split('-')
                if len(parts) == 3 and len(parts[0]) <= 2:
                    # DD-MM-YYYY format
                    dob = f"{parts[2]}-{parts[1]}-{parts[0]}"
                else:
                    # Already in YYYY-MM-DD format
                    dob = dob_raw
            elif '/' in dob_raw:
                # DD/MM/YYYY format
                parts = dob_raw.split('/')
                if len(parts) == 3:
                    dob = f"{parts[2]}-{parts[1]}-{parts[0]}"
            else:
                dob = dob_raw
            logger.info(f"[PREBOARDING] Converted DOB from '{dob_raw}' to '{dob}'")
        except Exception as e:
            logger.warning(f"[PREBOARDING] Could not convert DOB format: {e}")
            dob = dob_raw
    
    prefilled_data = {
        'email': user_email,
        'pan_number': pan_verification.pan_number if pan_verification else '',
        'full_name': full_name,
        'dob': dob,
        'gender': aadhaar_verification.gender if aadhaar_verification else '',
        'father_name': father_name,  # Extracted from Aadhaar careOf field
        'permanent_address': aadhaar_verification.address if aadhaar_verification else '',
        'bank_name': bank_verification.bank_name if bank_verification else '',
        'bank_account_number': bank_verification.account_number if bank_verification else '',
        'bank_ifsc': bank_verification.ifsc_code if bank_verification else '',
        'uan': '',
        'previous_joining_date': '',
        'company_name': '',
    }
    
    # Extract UAN from salary slip OCR data
    if doc_verification:
        for slip_num in [1, 2, 3]:
            ocr_data_attr = f'salary_slip_{slip_num}_ocr_data'
            ocr_data = getattr(doc_verification, ocr_data_attr, None)
            if ocr_data and isinstance(ocr_data, dict):
                if ocr_data.get('uan_number'):
                    prefilled_data['uan'] = ocr_data['uan_number']
                if ocr_data.get('company_name') and not prefilled_data['company_name']:
                    prefilled_data['company_name'] = ocr_data['company_name']
        
        # Extract joining date from offer letter OCR data
        if doc_verification.offer_letter_ocr_data:
            offer_data = doc_verification.offer_letter_ocr_data
            if isinstance(offer_data, dict) and offer_data.get('joining_date'):
                prefilled_data['previous_joining_date'] = offer_data['joining_date']
    
    logger.info(f"[PREBOARDING] Serving preboarding page for {user_email} with pre-filled data")
    return render_template('preboarding.html', data=prefilled_data)


@app.route('/submit-preboarding', methods=['POST'])
@login_required
def submit_preboarding():
    """Handle preboarding form submission and save to session"""
    try:
        user_email = session.get('user', 'unknown')
        
        # Check if user has already submitted preboarding
        if db_session:
            existing_preboarding = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
            if existing_preboarding and existing_preboarding.email and existing_preboarding.phone:
                logger.warning(f"[PREBOARDING] User {user_email} attempted duplicate submission")
                return jsonify({
                    'success': False,
                    'error': 'You have already submitted the pre-boarding form. Please proceed to onboarding.'
                }), 400
        
        data = request.form.to_dict()
        
        # Regex patterns for validation
        patterns = {
            'pan_number': r'^[A-Z]{5}[0-9]{4}[A-Z]$',  # ABCDE1234F
            'aadhaar_number': r'^\d{12}$',  # 12 digits
            'uan': r'^\d{12}$',  # 12 digits
            'mobile': r'^[6-9]\d{9}$',  # Indian mobile: 10 digits starting with 6-9
            'pincode': r'^\d{6}$',  # 6 digits
            'bank_account_number': r'^\d{9,18}$',  # 9-18 digits
            'bank_ifsc': r'^[A-Z]{4}0[A-Z0-9]{6}$',  # IFSC format
            'emergency_contact': r'^[6-9]\d{9}$',  # Same as mobile
        }
        
        # Validate important fields
        errors = []
        
        # PAN validation
        if data.get('pan_number'):
            if not re.match(patterns['pan_number'], data['pan_number'].strip().upper()):
                errors.append('Invalid PAN format. Should be like ABCDE1234F')
        
        # Aadhaar validation (if provided)
        if data.get('aadhaar_number'):
            aadhaar = data['aadhaar_number'].strip().replace(' ', '').replace('-', '')
            if not re.match(patterns['aadhaar_number'], aadhaar):
                errors.append('Invalid Aadhaar number. Must be 12 digits')
        
        # UAN validation (if provided)
        if data.get('uan') and data['uan'].strip():
            if not re.match(patterns['uan'], data['uan'].strip()):
                errors.append('Invalid UAN. Must be 12 digits')
        
        # Mobile validation
        if data.get('mobile'):
            if not re.match(patterns['mobile'], data['mobile'].strip()):
                errors.append('Invalid mobile number. Must be 10 digits starting with 6-9')
        
        # Emergency contact validation
        if data.get('emergency_contact'):
            if not re.match(patterns['emergency_contact'], data['emergency_contact'].strip()):
                errors.append('Invalid emergency contact. Must be 10 digits starting with 6-9')
        
        # Current address pincode
        if data.get('current_pincode'):
            if not re.match(patterns['pincode'], data['current_pincode'].strip()):
                errors.append('Invalid current address pincode. Must be 6 digits')
        
        # Permanent address pincode
        if data.get('permanent_pincode'):
            if not re.match(patterns['pincode'], data['permanent_pincode'].strip()):
                errors.append('Invalid permanent address pincode. Must be 6 digits')
        
        # Bank account validation
        if data.get('bank_account_number'):
            if not re.match(patterns['bank_account_number'], data['bank_account_number'].strip()):
                errors.append('Invalid bank account number. Must be 9-18 digits')
        
        # IFSC validation
        if data.get('bank_ifsc'):
            if not re.match(patterns['bank_ifsc'], data['bank_ifsc'].strip().upper()):
                errors.append('Invalid IFSC code. Format: ABCD0123456')
        
        # If validation errors, return them
        if errors:
            logger.warning(f"[PREBOARDING] Validation errors for {user_email}: {errors}")
            return jsonify({
                'success': False,
                'error': ' | '.join(errors)
            }), 400
        
        # Handle file uploads for preboarding documents
        safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
        upload_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'documents')
        os.makedirs(upload_dir, exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        file_urls = {}
        
        # Handle qualification document
        if 'qualification_document' in request.files:
            file = request.files['qualification_document']
            if file and file.filename:
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'pdf'
                local_filename = f"qualification_doc_{timestamp}.{file_ext}"
                filepath = os.path.join(upload_dir, local_filename)
                file.save(filepath)
                file_urls['qualification_document'] = f"/uploads/{safe_email}/documents/{local_filename}"
                logger.info(f"[PREBOARDING] Qualification document saved: {filepath}")
        
        # Handle PAN card
        if 'pan_card' in request.files:
            file = request.files['pan_card']
            if file and file.filename:
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'pdf'
                local_filename = f"pan_card_{timestamp}.{file_ext}"
                filepath = os.path.join(upload_dir, local_filename)
                file.save(filepath)
                file_urls['pan_card'] = f"/uploads/{safe_email}/documents/{local_filename}"
                logger.info(f"[PREBOARDING] PAN card saved: {filepath}")
        
        # Handle Aadhaar card
        if 'aadhaar_card' in request.files:
            file = request.files['aadhaar_card']
            if file and file.filename:
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'pdf'
                local_filename = f"aadhaar_card_{timestamp}.{file_ext}"
                filepath = os.path.join(upload_dir, local_filename)
                file.save(filepath)
                file_urls['aadhaar_card'] = f"/uploads/{safe_email}/documents/{local_filename}"
                logger.info(f"[PREBOARDING] Aadhaar card saved: {filepath}")
        
        # Save preboarding data to database
        if db_session:
            try:
                # Check if record already exists
                existing_record = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
                
                if existing_record:
                    # Update existing record with preboarding data
                    existing_record.email = data.get('email')
                    existing_record.phone = data.get('phone')
                    existing_record.highest_qualification = data.get('highest_qualification')
                    existing_record.college_name = data.get('college_name')
                    existing_record.pan_number = data.get('pan_number')
                    existing_record.aadhaar_number = data.get('aadhaar_number')
                    existing_record.current_address = data.get('current_address')
                    
                    # Store file URLs
                    if file_urls.get('qualification_document'):
                        existing_record.attachment_1_url = file_urls['qualification_document']
                    if file_urls.get('pan_card'):
                        existing_record.attachment_2_url = file_urls['pan_card']
                    if file_urls.get('aadhaar_card'):
                        existing_record.attachment_3_url = file_urls['aadhaar_card']
                    
                    existing_record.updated_at = datetime.now()
                    logger.info(f"[PREBOARDING] Updated existing record for {user_email}")
                else:
                    # Create new record with preboarding data
                    new_record = OnboardingData(
                        user_email=user_email,
                        email=data.get('email'),
                        phone=data.get('phone'),
                        highest_qualification=data.get('highest_qualification'),
                        college_name=data.get('college_name'),
                        pan_number=data.get('pan_number'),
                        aadhaar_number=data.get('aadhaar_number'),
                        current_address=data.get('current_address'),
                        attachment_1_url=file_urls.get('qualification_document'),
                        attachment_2_url=file_urls.get('pan_card'),
                        attachment_3_url=file_urls.get('aadhaar_card'),
                        survey_completed=False
                    )
                    db_session.add(new_record)
                    logger.info(f"[PREBOARDING] Created new record for {user_email}")
                
                db_session.commit()
                logger.info(f"[PREBOARDING] Preboarding data saved to database for {user_email}")
                
                # Send preboarding confirmation email to user
                user_name = data.get('email', user_email).split('@')[0]
                try:
                    email_result = send_preboarding_confirmation(user_email, user_name)
                    logger.info(f"[PREBOARDING] Email result: {email_result['message']}")
                except Exception as email_error:
                    logger.error(f"[PREBOARDING] Failed to send confirmation email: {email_error}")
                
                # Also store in session for backward compatibility
                session['preboarding_data'] = data
                
                return jsonify({
                    'success': True,
                    'message': 'Pre-boarding form submitted successfully!',
                    'redirect': '/onboarding'
                })
                
            except Exception as db_error:
                db_session.rollback()
                logger.error(f"[PREBOARDING] Database error: {db_error}")
                return jsonify({'success': False, 'error': 'Failed to save preboarding data'}), 500
        else:
            return jsonify({'success': False, 'error': 'Database connection not available'}), 500
        
    except Exception as e:
        logger.error(f"[PREBOARDING] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/onboarding')
@login_required
def onboarding_page():
    """Render onboarding page"""
    user_email = session.get('user', 'unknown')
    
    # Check if preboarding was completed (check database)
    if db_session:
        preboarding_record = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
        if not preboarding_record or not preboarding_record.email or not preboarding_record.phone:
            logger.warning(f"[ONBOARDING] User {user_email} tried to access onboarding without completing preboarding")
            return redirect(url_for('preboarding_page'))
    
    # Fetch existing verification data for pre-filling
    pan_verification = db_session.query(PANVerification).filter_by(user_email=user_email).first()
    
    # For Aadhaar, prefer DigiLocker verification over manual upload
    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
        user_email=user_email, 
        verification_method='digilocker'
    ).first()
    
    if not aadhaar_verification:
        aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
            user_email=user_email
        ).first()
    
    bank_verification = db_session.query(BankVerification).filter_by(user_email=user_email).first()
    doc_verification = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
    
    # Prepare pre-filled data
    full_name = ''
    if aadhaar_verification and aadhaar_verification.full_name:
        full_name = aadhaar_verification.full_name
    elif pan_verification and pan_verification.full_name:
        full_name = pan_verification.full_name
    
    # Extract father/husband name from Aadhaar careOf field
    father_name = ''
    if aadhaar_verification and aadhaar_verification.verification_data:
        verification_data = aadhaar_verification.verification_data
        if isinstance(verification_data, dict):
            father_name = verification_data.get('care_of', '')
    
    # Convert DOB format from DD-MM-YYYY to YYYY-MM-DD for HTML date input
    dob = ''
    if aadhaar_verification and aadhaar_verification.date_of_birth:
        dob_raw = aadhaar_verification.date_of_birth
        try:
            if '-' in dob_raw:
                parts = dob_raw.split('-')
                if len(parts) == 3 and len(parts[0]) <= 2:
                    dob = f"{parts[2]}-{parts[1]}-{parts[0]}"
                else:
                    dob = dob_raw
            elif '/' in dob_raw:
                parts = dob_raw.split('/')
                if len(parts) == 3:
                    dob = f"{parts[2]}-{parts[1]}-{parts[0]}"
            else:
                dob = dob_raw
        except Exception as e:
            logger.warning(f"[ONBOARDING] Could not convert DOB format: {e}")
            dob = dob_raw
    
    # Get permanent address from Aadhaar - handle None values properly
    permanent_address = ''
    if aadhaar_verification:
        if aadhaar_verification.address and aadhaar_verification.address != 'None':
            permanent_address = aadhaar_verification.address
        elif aadhaar_verification.verification_data and isinstance(aadhaar_verification.verification_data, dict):
            # Try to get address from verification_data JSON if not in address field
            # Navigate nested structure: verification_data -> aadhaar -> aadhaar -> address
            aadhaar_info = aadhaar_verification.verification_data.get('aadhaar', {})
            if isinstance(aadhaar_info, dict) and 'aadhaar' in aadhaar_info:
                aadhaar_details = aadhaar_info['aadhaar']
            else:
                aadhaar_details = aadhaar_info
            
            addr_data = aadhaar_details.get('address', {})
            if isinstance(addr_data, dict):
                address_parts = [
                    addr_data.get('careOf'),
                    addr_data.get('house'),
                    addr_data.get('street'),
                    addr_data.get('locality'),
                    addr_data.get('vtc'),
                    addr_data.get('district'),
                    addr_data.get('state'),
                    f"PIN: {addr_data.get('pin')}" if addr_data.get('pin') else None
                ]
                permanent_address = ', '.join([p for p in address_parts if p])
    
    prefilled_data = {
        'full_name': full_name,
        'dob': dob,
        'father_name': father_name,
        'gender': aadhaar_verification.gender if aadhaar_verification else '',
        'permanent_address': permanent_address,
        'bank_name': bank_verification.bank_name if bank_verification else '',
        'bank_account_number': bank_verification.account_number if bank_verification else '',
        'bank_ifsc': bank_verification.ifsc_code if bank_verification else '',
        'uan': '',
    }
    
    # Extract UAN from salary slip OCR data
    if doc_verification:
        for slip_num in [1, 2, 3]:
            ocr_data_attr = f'salary_slip_{slip_num}_ocr_data'
            ocr_data = getattr(doc_verification, ocr_data_attr, None)
            if ocr_data and isinstance(ocr_data, dict):
                if ocr_data.get('uan_number'):
                    prefilled_data['uan'] = ocr_data['uan_number']
                    break
    
    logger.info(f"[ONBOARDING] Serving onboarding page for {user_email} with pre-filled data")
    return render_template('onboarding.html', data=prefilled_data)


@app.route('/submit-onboarding', methods=['POST'])
@login_required
def submit_onboarding():
    """Handle onboarding form submission with file upload"""
    try:
        user_email = session.get('user', 'unknown')
        
        # Get preboarding data from session
        preboarding_data = session.get('preboarding_data', {})
        
        # If no preboarding data in session, try to reconstruct from database
        if not preboarding_data and db_session:
            logger.warning(f"[ONBOARDING] Preboarding data not in session, reconstructing from database for {user_email}")
            try:
                pan_verification = db_session.query(PANVerification).filter_by(user_email=user_email).first()
                aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
                    user_email=user_email,
                    verification_method='digilocker'
                ).first()
                if not aadhaar_verification:
                    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(user_email=user_email).first()
                bank_verification = db_session.query(BankVerification).filter_by(user_email=user_email).first()
                
                # Reconstruct survey data from verifications
                # Extract father_name from Aadhaar careOf field
                father_name = ''
                if aadhaar_verification and aadhaar_verification.verification_data:
                    verification_data = aadhaar_verification.verification_data
                    if isinstance(verification_data, dict):
                        father_name = verification_data.get('care_of', '')
                
                preboarding_data = {
                    'email': user_email,
                    'pan_number': pan_verification.pan_number if pan_verification else '',
                    'full_name': (aadhaar_verification.full_name if aadhaar_verification and aadhaar_verification.full_name else 
                                 (pan_verification.full_name if pan_verification else '')),
                    'dob': aadhaar_verification.date_of_birth if aadhaar_verification else '',
                    'gender': aadhaar_verification.gender if aadhaar_verification else '',
                    'father_name': father_name,  # Extracted from Aadhaar careOf field
                    'permanent_address': aadhaar_verification.address if aadhaar_verification else '',
                    'bank_name': bank_verification.bank_name if bank_verification else '',
                    'bank_account_number': bank_verification.account_number if bank_verification else '',
                    'bank_ifsc': bank_verification.ifsc_code if bank_verification else '',
                }
                logger.info(f"[ONBOARDING] Reconstructed preboarding data from database")
            except Exception as e:
                logger.error(f"[ONBOARDING] Failed to reconstruct preboarding data: {e}")
                return jsonify({'success': False, 'error': 'Please complete the preboarding form first'}), 400
        
        if not preboarding_data:
            return jsonify({'success': False, 'error': 'Please complete the preboarding form first'}), 400
        
        # Get additional form data
        additional_data = request.form.to_dict()
        
        # Handle passport photo upload
        passport_photo_url = None
        if 'passport_photo' in request.files:
            file = request.files['passport_photo']
            if file and file.filename:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
                file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else 'jpg'
                
                # Upload to local storage (S3 disabled for now)
                upload_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'documents')
                os.makedirs(upload_dir, exist_ok=True)
                local_filename = f"passport_photo_{timestamp}.{file_ext}"
                filepath = os.path.join(upload_dir, local_filename)
                file.save(filepath)
                passport_photo_url = f"/uploads/{safe_email}/documents/{local_filename}"
                logger.info(f"[LOCAL] Passport photo saved: {filepath}")
                
                # S3 upload (uncomment when needed)
                # s3_key = f"{safe_email}/documents/passport_photo_{timestamp}.{file_ext}"
                # if s3_client and S3_BUCKET_NAME:
                #     try:
                #         with open(filepath, 'rb') as f:
                #             s3_client.put_object(
                #                 Bucket=S3_BUCKET_NAME,
                #                 Key=s3_key,
                #                 Body=f.read(),
                #                 ContentType=f'image/{file_ext}',
                #                 Metadata={'user_email': user_email, 'document_type': 'passport_photo'}
                #             )
                #         passport_photo_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                #         logger.info(f"[S3] Passport photo uploaded: {s3_key}")
                #     except Exception as e:
                #         logger.warning(f"[S3] Failed to upload passport photo: {e}")
        
        # Combine all data
        complete_data = {**preboarding_data, **additional_data, 'passport_photo_url': passport_photo_url}
        
        # Log mobile from form
        if 'mobile' in complete_data:
            logger.info(f"[FORM DATA] Using mobile from survey form: {complete_data['mobile']}")
        
        # Get gender and address from Aadhaar verification if available
        if db_session:
            try:
                # Fetch PAN verification for name (PF forms are linked to PAN)
                pan_verification = db_session.query(PANVerification).filter_by(
                    user_email=user_email
                ).order_by(PANVerification.created_at.desc()).first()
                
                if pan_verification and pan_verification.full_name:
                    complete_data['pan_full_name'] = pan_verification.full_name
                    logger.info(f"[PF FORM] Using full name from PAN: {pan_verification.full_name}")
                
                # Add PAN number to complete_data
                if pan_verification and pan_verification.pan_number:
                    complete_data['pan'] = pan_verification.pan_number
                    logger.info(f"[FORM DATA] PAN number: {pan_verification.pan_number}")
                
                # Fetch Aadhaar verification for other details - prefer DigiLocker over manual upload
                aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
                    user_email=user_email,
                    verification_method='digilocker'
                ).first()
                
                # If no DigiLocker verification, fall back to manual upload
                if not aadhaar_verification:
                    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
                        user_email=user_email
                    ).first()
                
                if aadhaar_verification:
                    if aadhaar_verification.full_name:
                        complete_data['aadhaar_full_name'] = aadhaar_verification.full_name
                        logger.info(f"[PF FORM] Using full name from Aadhaar: {aadhaar_verification.full_name}")
                    
                    if aadhaar_verification.date_of_birth:
                        complete_data['aadhaar_dob'] = aadhaar_verification.date_of_birth
                        logger.info(f"[PF FORM] Using DOB from Aadhaar: {aadhaar_verification.date_of_birth}")
                    
                    if aadhaar_verification.gender:
                        complete_data['aadhaar_gender'] = aadhaar_verification.gender
                        logger.info(f"[PF FORM] Using gender from Aadhaar: {aadhaar_verification.gender}")
                    
                    if aadhaar_verification.address:
                        # Use Aadhaar address if permanent address not in survey
                        if not complete_data.get('permanent_address'):
                            complete_data['permanent_address'] = aadhaar_verification.address
                            logger.info(f"[PF FORM] Using address from Aadhaar verification")
                    
                    # Add Aadhaar number to complete_data (mask for security - last 4 digits)
                    if hasattr(aadhaar_verification, 'aadhaar_number') and aadhaar_verification.aadhaar_number:
                        complete_data['aadhaar'] = aadhaar_verification.aadhaar_number
                        logger.info(f"[FORM DATA] Aadhaar number added")
                
                # Fetch Bank verification for bank details
                bank_verification = db_session.query(BankVerification).filter_by(
                    user_email=user_email
                ).order_by(BankVerification.created_at.desc()).first()
                
                if bank_verification:
                    if bank_verification.account_number:
                        complete_data['account_number'] = bank_verification.account_number
                        logger.info(f"[FORM DATA] Account number added")
                    
                    if bank_verification.ifsc_code:
                        complete_data['ifsc'] = bank_verification.ifsc_code
                        logger.info(f"[FORM DATA] IFSC code: {bank_verification.ifsc_code}")
                    
                    if hasattr(bank_verification, 'bank_name') and bank_verification.bank_name:
                        complete_data['bank_name'] = bank_verification.bank_name
                        logger.info(f"[FORM DATA] Bank name: {bank_verification.bank_name}")
                    elif hasattr(bank_verification, 'beneficiary_name') and bank_verification.beneficiary_name:
                        complete_data['bank_name'] = bank_verification.beneficiary_name
                        logger.info(f"[FORM DATA] Bank name from beneficiary: {bank_verification.beneficiary_name}")
                        
            except Exception as e:
                logger.warning(f"[PF FORM] Could not fetch Aadhaar data: {e}")
        
        # Save onboarding data to database (update existing record from preboarding)
        if db_session:
            try:
                # Get existing record (should exist from preboarding submission)
                existing_survey = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
                
                if existing_survey:
                    # Update existing record with onboarding data
                    existing_survey.full_name = complete_data.get('full_name')
                    existing_survey.dob = complete_data.get('dob')
                    existing_survey.mother_name = complete_data.get('mother_name')
                    existing_survey.father_name = complete_data.get('father_name')
                    existing_survey.gender = complete_data.get('gender')
                    existing_survey.marital_status = complete_data.get('marital_status')
                    existing_survey.blood_group = complete_data.get('blood_group')
                    existing_survey.permanent_address = complete_data.get('permanent_address')
                    existing_survey.emergency_contact = complete_data.get('emergency_contact')
                    existing_survey.bank_name = complete_data.get('bank_name')
                    existing_survey.bank_account_number = complete_data.get('bank_account_number')
                    existing_survey.bank_ifsc = complete_data.get('bank_ifsc')
                    existing_survey.previous_establishment = complete_data.get('previous_establishment')
                    existing_survey.uan = complete_data.get('uan')
                    existing_survey.previous_pf_number = complete_data.get('previous_pf_number')
                    existing_survey.previous_joining_date = complete_data.get('previous_joining_date')
                    existing_survey.previous_exit_date = complete_data.get('previous_exit_date')
                    existing_survey.epf_member = complete_data.get('epf_member')
                    existing_survey.eps_member = complete_data.get('eps_member')
                    
                    # Handle multiple PF nominees
                    pf_nominees = []
                    if 'pf_nominee_name[]' in additional_data:
                        nominee_names = request.form.getlist('pf_nominee_name[]')
                        nominee_dobs = request.form.getlist('pf_nominee_dob[]')
                        nominee_relationships = request.form.getlist('pf_nominee_relationship[]')
                        nominee_addresses = request.form.getlist('pf_nominee_address[]')
                        nominee_shares = request.form.getlist('pf_nominee_share[]')
                        nominee_guardians = request.form.getlist('pf_minor_guardian_details[]')
                        
                        # Validate total share doesn't exceed 100%
                        total_share = 0
                        for share in nominee_shares:
                            if share.strip():
                                try:
                                    total_share += float(share)
                                except ValueError:
                                    logger.error(f"[ONBOARDING] Invalid nominee share value: {share}")
                        
                        if total_share > 100:
                            logger.error(f"[ONBOARDING] Total nominee share ({total_share}%) exceeds 100%")
                            return jsonify({
                                'success': False,
                                'error': f'Total nominee share cannot exceed 100%. Current total: {total_share}%'
                            }), 400
                        
                        for i in range(len(nominee_names)):
                            if nominee_names[i].strip():
                                pf_nominees.append({
                                    'name': nominee_names[i],
                                    'dob': nominee_dobs[i] if i < len(nominee_dobs) else '',
                                    'relationship': nominee_relationships[i] if i < len(nominee_relationships) else '',
                                    'address': nominee_addresses[i] if i < len(nominee_addresses) else '',
                                    'share': nominee_shares[i] if i < len(nominee_shares) else '',
                                    'guardian_details': nominee_guardians[i] if i < len(nominee_guardians) else ''
                                })
                    existing_survey.pf_nominees = pf_nominees
                    
                    # Handle multiple insurance dependents
                    insurance_dependents = []
                    if 'insurance_dependent_name[]' in additional_data:
                        dependent_relations = request.form.getlist('insurance_dependent_relation[]')
                        dependent_names = request.form.getlist('insurance_dependent_name[]')
                        dependent_dobs = request.form.getlist('insurance_dependent_dob[]')
                        
                        for i in range(len(dependent_names)):
                            if dependent_names[i].strip():
                                insurance_dependents.append({
                                    'relation': dependent_relations[i] if i < len(dependent_relations) else '',
                                    'name': dependent_names[i],
                                    'dob': dependent_dobs[i] if i < len(dependent_dobs) else ''
                                })
                    existing_survey.insurance_dependents = insurance_dependents
                    
                    # Handle pension details
                    existing_survey.pension_details = {
                        'pension_member_name': complete_data.get('pension_member_name'),
                        'pension_member_dob': complete_data.get('pension_member_dob'),
                        'pension_member_relationship': complete_data.get('pension_member_relationship'),
                        'widow_pension_name': complete_data.get('widow_pension_name'),
                        'widow_pension_dob': complete_data.get('widow_pension_dob'),
                        'widow_pension_relationship': complete_data.get('widow_pension_relationship')
                    }
                    existing_survey.hobbies = complete_data.get('hobbies')
                    existing_survey.fun_fact = complete_data.get('fun_fact')
                    existing_survey.favourite_quote = complete_data.get('favourite_quote')
                    existing_survey.dream_in_life = complete_data.get('dream_in_life')
                    existing_survey.tshirt_size = complete_data.get('tshirt_size')
                    existing_survey.parking_required = complete_data.get('parking_required')
                    existing_survey.passport_photo_url = passport_photo_url
                    existing_survey.survey_completed = True
                    existing_survey.updated_at = datetime.utcnow()
                    logger.info(f"[DB] Updated existing onboarding record for {user_email}")
                else:
                    # Create new record if preboarding wasn't done (fallback)
                    new_survey = OnboardingData(
                        user_email=user_email,
                        full_name=complete_data.get('full_name'),
                        email=complete_data.get('email'),
                        phone=complete_data.get('phone'),
                        pan_number=complete_data.get('pan_number'),
                        aadhaar_number=complete_data.get('aadhaar_number'),
                        dob=complete_data.get('dob'),
                        mother_name=complete_data.get('mother_name'),
                        father_name=complete_data.get('father_name'),
                        gender=complete_data.get('gender'),
                        marital_status=complete_data.get('marital_status'),
                        blood_group=complete_data.get('blood_group'),
                        permanent_address=complete_data.get('permanent_address'),
                        current_address=complete_data.get('current_address'),
                        emergency_contact=complete_data.get('emergency_contact'),
                        bank_name=complete_data.get('bank_name'),
                        bank_account_number=complete_data.get('bank_account_number'),
                        bank_ifsc=complete_data.get('bank_ifsc'),
                        previous_establishment=complete_data.get('previous_establishment'),
                        uan=complete_data.get('uan'),
                        previous_pf_number=complete_data.get('previous_pf_number'),
                        previous_joining_date=complete_data.get('previous_joining_date'),
                        previous_exit_date=complete_data.get('previous_exit_date'),
                        epf_member=complete_data.get('epf_member'),
                        eps_member=complete_data.get('eps_member'),
                        pf_nominees=pf_nominees,
                        insurance_dependents=insurance_dependents,
                        pension_details={
                            'pension_member_name': complete_data.get('pension_member_name'),
                            'pension_member_dob': complete_data.get('pension_member_dob'),
                            'pension_member_relationship': complete_data.get('pension_member_relationship'),
                            'widow_pension_name': complete_data.get('widow_pension_name'),
                            'widow_pension_dob': complete_data.get('widow_pension_dob'),
                            'widow_pension_relationship': complete_data.get('widow_pension_relationship')
                        },
                        hobbies=complete_data.get('hobbies'),
                        fun_fact=complete_data.get('fun_fact'),
                        favourite_quote=complete_data.get('favourite_quote'),
                        dream_in_life=complete_data.get('dream_in_life'),
                        tshirt_size=complete_data.get('tshirt_size'),
                        parking_required=complete_data.get('parking_required'),
                        passport_photo_url=passport_photo_url,
                        survey_completed=True
                    )
                    db_session.add(new_survey)
                    logger.info(f"[DB] Created new onboarding record for {user_email}")
                
                db_session.commit()
                logger.info(f"[DB] ✓ Onboarding data saved to database successfully")
                
            except Exception as e:
                db_session.rollback()
                logger.error(f"[DB] Failed to save survey to database: {e}")
        
        logger.info(f"[ONBOARDING] Complete onboarding submitted by {user_email}")
        
        # Send onboarding completion email to user
        user_name = complete_data.get('full_name', user_email.split('@')[0])
        try:
            email_result = send_onboarding_confirmation(user_email, user_name)
            logger.info(f"[ONBOARDING] Confirmation email result: {email_result['message']}")
        except Exception as email_error:
            logger.error(f"[ONBOARDING] Failed to send confirmation email: {email_error}")
        
        # Fetch complete data from database for PF and Form 11 generation
        form_data = {}
        if db_session:
            try:
                # Fetch survey data from database
                survey_record = db_session.query(OnboardingData).filter_by(user_email=user_email).first()
                
                if survey_record:
                    # Convert database model to dictionary
                    form_data = {
                        'full_name': survey_record.full_name,
                        'email': survey_record.email,
                        'phone': survey_record.phone,
                        'pan_number': survey_record.pan_number,
                        'aadhaar_number': survey_record.aadhaar_number,
                        'dob': survey_record.dob,
                        'mother_name': survey_record.mother_name,
                        'father_name': survey_record.father_name,
                        'gender': survey_record.gender,
                        'marital_status': survey_record.marital_status,
                        'permanent_address': survey_record.permanent_address,
                        'current_address': survey_record.current_address,
                        'previous_establishment': survey_record.previous_establishment,
                        'uan': survey_record.uan,
                        'previous_pf_number': survey_record.previous_pf_number,
                        'previous_joining_date': survey_record.previous_joining_date,
                        'previous_exit_date': survey_record.previous_exit_date,
                        'epf_member': survey_record.epf_member,
                        'eps_member': survey_record.eps_member,
                        'pf_nominees': survey_record.pf_nominees or [],
                        'pension_details': survey_record.pension_details or {},
                        'hobbies': survey_record.hobbies,
                        'fun_fact': survey_record.fun_fact,
                        'favourite_quote': survey_record.favourite_quote,
                        'dream_in_life': survey_record.dream_in_life,
                        'tshirt_size': survey_record.tshirt_size,
                        'parking_required': survey_record.parking_required,
                        'passport_photo_url': survey_record.passport_photo_url,
                    }
                    logger.info(f"[DB] Fetched survey data from database for PF/Form11 generation")
                else:
                    logger.warning(f"[DB] No survey record found, using session data")
                    form_data = complete_data
                    
                # Fetch PAN verification data
                pan_verification = db_session.query(PANVerification).filter_by(
                    user_email=user_email
                ).order_by(PANVerification.created_at.desc()).first()
                
                if pan_verification:
                    form_data['pan_full_name'] = pan_verification.full_name
                    form_data['pan'] = pan_verification.pan_number
                    logger.info(f"[DB] Fetched PAN data: {pan_verification.full_name}")
                
                # Fetch Aadhaar verification data
                aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
                    user_email=user_email,
                    verification_method='digilocker'
                ).first()
                
                if not aadhaar_verification:
                    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(
                        user_email=user_email
                    ).first()
                
                if aadhaar_verification:
                    form_data['aadhaar_full_name'] = aadhaar_verification.full_name
                    form_data['aadhaar_dob'] = aadhaar_verification.date_of_birth
                    form_data['aadhaar_gender'] = aadhaar_verification.gender
                    form_data['aadhaar'] = aadhaar_verification.aadhaar_number
                    if not form_data.get('permanent_address') and aadhaar_verification.address:
                        form_data['permanent_address'] = aadhaar_verification.address
                    logger.info(f"[DB] Fetched Aadhaar data: {aadhaar_verification.full_name}")
                
                # Fetch Bank verification data
                bank_verification = db_session.query(BankVerification).filter_by(
                    user_email=user_email
                ).order_by(BankVerification.created_at.desc()).first()
                
                if bank_verification:
                    form_data['account_number'] = bank_verification.account_number
                    form_data['ifsc'] = bank_verification.ifsc_code
                    form_data['bank_name'] = bank_verification.bank_name or bank_verification.beneficiary_name
                    masked_account = f"****{bank_verification.account_number[-4:]}" if bank_verification.account_number and len(bank_verification.account_number) >= 4 else "****"
                    logger.info(f"[DB] Fetched Bank data (masked account): {masked_account}")
                    
            except Exception as e:
                logger.error(f"[DB] Failed to fetch form data from database: {e}")
                form_data = complete_data
        else:
            form_data = complete_data
        
        logger.info(f"[FORM DATA] Using data from database for PF and Form 11 generation")
        
        # Generate PF form and save locally
        try:
            logger.info(f"[PF FORM] Generating PF form for {user_email}")
            pf_form_path = create_pf_form(form_data, user_email)
            logger.info(f"[PF FORM] ✓ PF form generated and saved: {pf_form_path}")
            
            complete_data['pf_form_generated'] = True
            complete_data['pf_form_path'] = pf_form_path
            
            # Send PF form via email
            user_name = form_data.get('full_name', user_email.split('@')[0])
            logger.info(f"[PF FORM] Sending PF form to company HR")
            email_result = send_pf_form_to_company(user_email, user_name, pf_form_path)
            logger.info(f"[PF FORM] Email result: {email_result['message']}")
            complete_data['pf_form_sent'] = (email_result.get('status') == 200)
            
        except Exception as e:
            logger.error(f"[PF FORM] Failed to generate PF form: {e}")
            complete_data['pf_form_error'] = str(e)
        
        # Generate Form 11 and save locally
        try:
            logger.info(f"[FORM 11] Generating Form 11 for {user_email}")
            form11_path = create_form11(form_data, user_email)
            logger.info(f"[FORM 11] ✓ Form 11 generated and saved: {form11_path}")
            
            complete_data['form11_generated'] = True
            complete_data['form11_path'] = form11_path
            
            # Send Form 11 via email
            import time
            time.sleep(2)
            
            user_name = form_data.get('full_name', user_email.split('@')[0])
            logger.info(f"[FORM 11] Sending Form 11 to company HR")
            email_result = send_form11_to_company(user_email, user_name, form11_path)
            logger.info(f"[FORM 11] Email result: {email_result['message']}")
            complete_data['form11_sent'] = (email_result.get('status') == 200)
            
        except Exception as e:
            logger.error(f"[FORM 11] Failed to generate Form 11: {e}")
            complete_data['form11_error'] = str(e)
        
        # Store additional data in session for form persistence (don't clear preboarding_data)
        session['additional_data'] = additional_data
        
        # Generate download URLs
        download_url = None
        form11_download_url = None
        
        if complete_data.get('pf_form_generated') and complete_data.get('pf_form_path'):
            # Convert absolute path to relative URL
            pf_form_filename = os.path.basename(complete_data['pf_form_path'])
            # download_url = f"/download-pf-form/{pf_form_filename}"
        
        if complete_data.get('form11_generated') and complete_data.get('form11_path'):
            # Convert absolute path to relative URL
            form11_filename = os.path.basename(complete_data['form11_path'])
            # form11_download_url = f"/download-form11/{form11_filename}"
        
        return jsonify({
            'success': True,
            'message': 'All details submitted successfully. PF Form and Form 11 generated!',
            'pf_form_generated': complete_data.get('pf_form_generated', False),
            'form11_generated': complete_data.get('form11_generated', False),
            'download_url': download_url,
            'form11_download_url': form11_download_url
        })
        
    except Exception as e:
        logger.error(f"[ONBOARDING] Error submitting onboarding details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500

@app.route('/download-form11/<filename>')
@login_required
def download_form11(filename):
    """Download generated Form 11"""
    form11_dir = os.path.join(os.getcwd(), 'uploads', 'form11_forms')
    logger.info(f"[DOWNLOAD] Serving Form 11: {filename}")
    return send_from_directory(form11_dir, filename, as_attachment=True)



@app.route('/uploads/<path:filepath>')
@login_required
def serve_uploaded_file(filepath):
    """Serve locally stored uploaded files with IDOR protection"""
    user_email = session.get('user', 'unknown')
    safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
    
    # Security: Only allow users to access their own files
    if not filepath.startswith(safe_email + '/'):
        logger.warning(f"[SECURITY] IDOR attempt: {user_email} tried to access {filepath}")
        abort(403, description="Access denied: You can only access your own files")
    
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    
    # Additional path traversal protection
    requested_path = os.path.normpath(os.path.join(uploads_dir, filepath))
    if not requested_path.startswith(os.path.normpath(uploads_dir)):
        logger.warning(f"[SECURITY] Path traversal attempt: {filepath}")
        abort(403, description="Access denied: Invalid file path")
    
    return send_from_directory(uploads_dir, filepath)

@app.route('/download-pf-form/<filename>')
@login_required
def download_pf_form(filename):
    """Download generated PF form"""
    try:
        pf_forms_dir = os.path.join(os.getcwd(), 'uploads', 'pf_forms')
        logger.info(f"[DOWNLOAD] Serving PF form: {filename}")
        return send_from_directory(pf_forms_dir, filename, as_attachment=True)
    except Exception as e:
        logger.error(f"[DOWNLOAD] Failed to serve PF form: {e}")
        abort(404, description="PF form not found")




@app.route('/')
@login_required
def index() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    # Redirect to next incomplete step
    user_email = session.get('user', 'unknown')
    next_step = get_next_verification_step(user_email)
    logger.info(f"[INDEX] Redirecting to {next_step}")
    return redirect(url_for(next_step))


@app.route('/pan-verification')
@login_required
def pan_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    user_email = session.get('user', 'unknown')
    status = get_verification_status(user_email)
    
    # If already completed, redirect to next step (prevent going back)
    if status['pan_completed']:
        logger.info(f"[PAN] Already completed, redirecting to next step")
        next_step = get_next_verification_step(user_email)
        return redirect(url_for(next_step))
    
    logger.info("[PAN VERIFICATION] Serving PAN verification page")
    return render_template('pan_verification.html')


@app.route('/aadhaar-verification')
@login_required
def aadhaar_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    user_email = session.get('user', 'unknown')
    status = get_verification_status(user_email)
    
    # Ensure PAN is completed first
    if not status['pan_completed']:
        logger.warning(f"[AADHAAR] PAN not completed, redirecting")
        return redirect(url_for('pan_verification'))
    
    # If already completed and NOT just returned from DigiLocker, redirect to next step
    # Allow user to see DigiLocker results even if already completed
    just_returned_from_digilocker = session.get('digilocker_success', False)
    if status['aadhaar_completed'] and not just_returned_from_digilocker:
        logger.info(f"[AADHAAR] Already completed, redirecting to next step")
        next_step = get_next_verification_step(user_email)
        return redirect(url_for(next_step))
    
    logger.info("[AADHAAR VERIFICATION] Serving Aadhaar verification page")
    return render_template('aadhaar_verification.html')


@app.route('/bank-verification')
@login_required
def bank_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    user_email = session.get('user', 'unknown')
    status = get_verification_status(user_email)
    
    # Ensure previous steps are completed
    if not status['pan_completed']:
        logger.warning(f"[BANK] PAN not completed, redirecting")
        return redirect(url_for('pan_verification'))
    if not status['aadhaar_completed']:
        logger.warning(f"[BANK] Aadhaar not completed, redirecting")
        return redirect(url_for('aadhaar_verification'))
    if not status['documents_completed']:
        logger.warning(f"[BANK] Documents not completed, redirecting")
        return redirect(url_for('document_verification'))
    
    # Bank verification can be accessed even if completed (allow back till here)
    logger.info("[BANK VERIFICATION] Serving Bank verification page")
    return render_template('bank_verification.html')


@app.route('/document-verification')
@login_required
def document_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    user_email = session.get('user', 'unknown')
    status = get_verification_status(user_email)
    
    # Ensure previous steps are completed
    if not status['pan_completed']:
        logger.warning(f"[DOCUMENTS] PAN not completed, redirecting")
        return redirect(url_for('pan_verification'))
    if not status['aadhaar_completed']:
        logger.warning(f"[DOCUMENTS] Aadhaar not completed, redirecting")
        return redirect(url_for('aadhaar_verification'))
    
    # If already completed, redirect to next step (prevent going back)
    if status['documents_completed']:
        logger.info(f"[DOCUMENTS] Already completed, redirecting to next step")
        next_step = get_next_verification_step(user_email)
        return redirect(url_for(next_step))
    
    # Check if documents already uploaded
    doc_record = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
    
    logger.info("[DOCUMENT VERIFICATION] Serving Document verification page")
    return render_template('document_verification.html', existing_docs=doc_record)


@app.route('/upload-document', methods=['POST'])
@login_required
def upload_document():
    """Upload documents (qualification certificate, offer letter, salary slips)"""
    try:
        user_email = session.get('user', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Get the document type from form
        doc_type = request.form.get('docType')  # 'qualification', 'offer_letter', 'salary_slip_1', etc.
        
        if not doc_type:
            return jsonify({'success': False, 'error': 'Document type is required'}), 400
        
        # Check if file is present
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file uploaded'}), 400
        
        file = request.files['file']
        
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'pdf', 'jpg', 'jpeg', 'png'}
        filename = file.filename.lower()
        file_ext = filename.rsplit('.', 1)[1] if '.' in filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({
                'success': False,
                'error': f'Invalid file type. Allowed: {", ".join(allowed_extensions)}'
            }), 400
        
        # Read file content
        file_content = file.read()
        
        # Validate file size (max 10MB)
        if len(file_content) > 10 * 1024 * 1024:
            return jsonify({'success': False, 'error': 'File size must be less than 10MB'}), 400
        
        # Generate S3 key
        
        safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
        s3_key = f"{safe_email}/documents/{doc_type}_{timestamp}.{file_ext}"
        
        file_url = None
        storage_location = None
        
        # Try to upload to S3 first
        if s3_client and S3_BUCKET_NAME:
            try:
                content_type_map = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'pdf': 'application/pdf'
                }
                content_type = content_type_map.get(file_ext, 'application/octet-stream')
                
                metadata = {
                    'user_email': user_email,
                    'document_type': doc_type,
                    'upload_time': timestamp
                }
                
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=file_content,
                    ContentType=content_type,
                    Metadata=metadata
                )
                
                file_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                storage_location = 's3'
                logger.info(f"[S3] Document uploaded successfully: {s3_key}")
            except Exception as e:
                logger.warning(f"[S3] Failed to upload to S3: {e}. Falling back to local storage.")
                storage_location = None
        
        # Fallback to local storage if S3 fails or not configured
        if not storage_location:
            try:
                # Create local uploads directory
                upload_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'documents')
                os.makedirs(upload_dir, exist_ok=True)
                
                # Save file locally
                local_filename = f"{doc_type}_{timestamp}.{file_ext}"
                local_path = os.path.join(upload_dir, local_filename)
                
                with open(local_path, 'wb') as f:
                    f.write(file_content)
                
                file_url = f"/uploads/{safe_email}/documents/{local_filename}"
                storage_location = 'local'
                logger.info(f"[LOCAL] Document saved locally: {local_path}")
            except Exception as e:
                logger.error(f"[LOCAL] Failed to save document locally: {e}")
                return jsonify({'success': False, 'error': 'Failed to save file to storage'}), 500
        
        # Save or update database record
        doc_record = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
        
        if not doc_record:
            doc_record = DocumentVerification(user_email=user_email)
            db_session.add(doc_record)
        
        # Process OCR for salary slips and offer letters
        ocr_data = None
        ocr_status = None
        
        if doc_type == 'qualification':
            logger.info(f"[OCR] Processing qualification certificate OCR for {file.filename}")
            try:
                is_valid, ocr_result = validate_and_extract_qualification_certificate(file_content, file.filename)
                if is_valid:
                    ocr_data = {
                        'student_name': ocr_result.get('student_name'),
                        'institution_name': ocr_result.get('institution_name'),
                        'qualification_type': ocr_result.get('qualification_type'),
                        'field_of_study': ocr_result.get('field_of_study'),
                        'completion_year': ocr_result.get('completion_year'),
                        'grade_or_percentage': ocr_result.get('grade_or_percentage'),
                        'extracted_at': datetime.utcnow().isoformat()
                    }
                    ocr_status = 'success'
                    logger.info(f"[OCR] Qualification certificate OCR successful: {ocr_data}")
                else:
                    ocr_status = 'failed'
                    ocr_data = {'error': ocr_result.get('error', 'Unknown error')}
                    logger.warning(f"[OCR] Qualification certificate OCR failed: {ocr_data}")
            except Exception as e:
                logger.error(f"[OCR] Qualification certificate OCR error: {e}")
                ocr_status = 'error'
                ocr_data = {'error': str(e)}
        
        elif doc_type == 'offer_letter':
            logger.info(f"[OCR] Processing offer letter OCR for {file.filename}")
            try:
                is_valid, ocr_result = validate_and_extract_offer_letter(file_content, file.filename)
                if is_valid:
                    ocr_data = {
                        'candidate_name': ocr_result.get('candidate_name'),
                        'company_name': ocr_result.get('company_name'),
                        'designation': ocr_result.get('designation'),
                        'joining_date': ocr_result.get('joining_date'),
                        'ctc': ocr_result.get('ctc'),
                        'extracted_at': datetime.utcnow().isoformat()
                    }
                    ocr_status = 'success'
                    logger.info(f"[OCR] Offer letter OCR successful: {ocr_data}")
                else:
                    ocr_status = 'failed'
                    ocr_data = {'error': ocr_result.get('error', 'Unknown error')}
                    logger.warning(f"[OCR] Offer letter OCR failed: {ocr_data}")
            except Exception as e:
                logger.error(f"[OCR] Offer letter OCR error: {e}")
                ocr_status = 'error'
                ocr_data = {'error': str(e)}
        
        elif doc_type in ['salary_slip_1', 'salary_slip_2', 'salary_slip_3']:
            logger.info(f"[OCR] Processing salary slip OCR for {file.filename}")
            try:
                is_valid, ocr_result = validate_and_extract_salary_slip(file_content, file.filename)
                if is_valid:
                    ocr_data = {
                        'employee_name': ocr_result.get('employee_name'),
                        'company_name': ocr_result.get('company_name'),
                        'month_year': ocr_result.get('month_year'),
                        'net_pay': ocr_result.get('net_pay'),
                        'gross_pay': ocr_result.get('gross_pay'),
                        'uan_number': ocr_result.get('uan_number'),
                        'extracted_at': datetime.utcnow().isoformat()
                    }
                    ocr_status = 'success'
                    logger.info(f"[OCR] Salary slip OCR successful: {ocr_data}")
                else:
                    ocr_status = 'failed'
                    ocr_data = {'error': ocr_result.get('error', 'Unknown error')}
                    logger.warning(f"[OCR] Salary slip OCR failed: {ocr_data}")
            except Exception as e:
                logger.error(f"[OCR] Salary slip OCR error: {e}")
                ocr_status = 'error'
                ocr_data = {'error': str(e)}
        
        # Update the appropriate field based on doc_type
        if doc_type == 'qualification':
            doc_record.qualification_certificate_s3_key = s3_key
            doc_record.qualification_certificate_s3_url = file_url
            doc_record.qualification_certificate_filename = file.filename
            doc_record.qualification_certificate_ocr_data = ocr_data
        elif doc_type == 'offer_letter':
            doc_record.offer_letter_s3_key = s3_key
            doc_record.offer_letter_s3_url = file_url
            doc_record.offer_letter_filename = file.filename
            doc_record.offer_letter_ocr_data = ocr_data
        elif doc_type == 'salary_slip_1':
            doc_record.salary_slip_1_s3_key = s3_key
            doc_record.salary_slip_1_s3_url = file_url
            doc_record.salary_slip_1_filename = file.filename
            doc_record.salary_slip_1_ocr_data = ocr_data
        elif doc_type == 'salary_slip_2':
            doc_record.salary_slip_2_s3_key = s3_key
            doc_record.salary_slip_2_s3_url = file_url
            doc_record.salary_slip_2_filename = file.filename
            doc_record.salary_slip_2_ocr_data = ocr_data
        elif doc_type == 'salary_slip_3':
            doc_record.salary_slip_3_s3_key = s3_key
            doc_record.salary_slip_3_s3_url = file_url
            doc_record.salary_slip_3_filename = file.filename
            doc_record.salary_slip_3_ocr_data = ocr_data
        
        # Update status - complete only if qualification certificate is uploaded
        if doc_record.qualification_certificate_s3_key:
            doc_record.status = 'complete'
        else:
            doc_record.status = 'incomplete'
        
        doc_record.uploaded_at = datetime.utcnow()
        
        db_session.commit()
        logger.info(f"[DB] Document {doc_type} saved for user: {user_email} (Storage: {storage_location})")
        
        response_data = {
            'success': True,
            'message': f'Document uploaded successfully (stored in {storage_location})',
            'docType': doc_type,
            'filename': file.filename,
            'url': file_url,
            'storage': storage_location,
            'status': doc_record.status
        }
        
        # Add OCR data to response if available
        if ocr_status:
            response_data['ocr_status'] = ocr_status
            response_data['ocr_data'] = ocr_data
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"[DOCUMENT UPLOAD] Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/delete-all-documents', methods=['POST'])
@login_required
def delete_all_documents():
    """Delete all documents for the current user"""
    try:
        user_email = session.get('user', 'unknown')
        
        # Get the document record
        doc_record = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
        
        if doc_record:
            # Clear all document fields
            doc_record.qualification_certificate_s3_key = None
            doc_record.qualification_certificate_s3_url = None
            doc_record.qualification_certificate_filename = None
            doc_record.qualification_certificate_ocr_data = None
            doc_record.offer_letter_s3_key = None
            doc_record.offer_letter_s3_url = None
            doc_record.offer_letter_filename = None
            doc_record.offer_letter_ocr_data = None
            doc_record.salary_slip_1_s3_key = None
            doc_record.salary_slip_1_s3_url = None
            doc_record.salary_slip_1_filename = None
            doc_record.salary_slip_1_ocr_data = None
            doc_record.salary_slip_2_s3_key = None
            doc_record.salary_slip_2_s3_url = None
            doc_record.salary_slip_2_filename = None
            doc_record.salary_slip_2_ocr_data = None
            doc_record.salary_slip_3_s3_key = None
            doc_record.salary_slip_3_s3_url = None
            doc_record.salary_slip_3_filename = None
            doc_record.salary_slip_3_ocr_data = None
            doc_record.status = 'incomplete'
            
            db_session.commit()
            logger.info(f"[DB] All documents cleared for user: {user_email}")
            
            return jsonify({
                'success': True,
                'message': 'All documents cleared successfully'
            })
        else:
            return jsonify({
                'success': True,
                'message': 'No documents found to clear'
            })
            
    except Exception as e:
        logger.error(f"[DELETE DOCUMENTS] Error: {e}")
        db_session.rollback()
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/verify-pan', methods=['POST'])
@login_required
def verify_pan() -> Any:
    pan_number = request.json.get('pan', '').upper()
    if not pan_number or not re.match(r'^[A-Z]{5}[0-9]{4}[A-Z]$', pan_number):
        abort(400, description="Invalid PAN number format")

    payload = {
        "pan": pan_number,
        "consent": "Y",
        "reason": "PAN verification for testing"
    }
    logger.info(f"[PAN] Verifying PAN: {pan_number}")
    logger.info(f"[PAN] Using API URL: {PAN_API_URL}")
    logger.info(f"[PAN] Headers: {dict((k, v if k != 'x-client-secret' else '***') for k, v in PAN_HEADERS.items())}")
    result = call_setu_api(PAN_API_URL, payload, PAN_HEADERS)
    
    # Save to database if verification successful
    if db_session and result.get('data'):
        try:
            user_email = session.get('user', 'unknown')
            pan_data = result.get('data', {})
            
            # Extract name from various possible fields
            full_name = (
                pan_data.get('full_name') or 
                pan_data.get('name') or 
                pan_data.get('fullName') or 
                pan_data.get('registered_name') or
                'N/A'
            )
            
            pan_verification = PANVerification(
                user_email=user_email,
                pan_number=pan_number,
                full_name=full_name,
                status=result.get('status', 'unknown'),
                verification_data=result
            )
            
            db_session.add(pan_verification)
            db_session.commit()
            logger.info(f"[DB] PAN verification saved for user: {user_email}")
        except Exception as e:
            logger.error(f"[DB] Failed to save PAN verification: {e}")
            db_session.rollback()
    
    return jsonify(result)


@app.route('/verify-bank', methods=['POST'])
@login_required
def verify_bank() -> Any:
    data: Dict[str, str] = request.json or {}
    ifsc = data.get('ifsc', '').upper()
    account_number = data.get('accountNumber', '').strip()

    if not ifsc or not account_number:
        abort(400, description="IFSC and Account Number are required")

    payload = {
        "ifsc": ifsc,
        "accountNumber": account_number
    }
    masked_account = f"****{account_number[-4:]}" if len(account_number) >= 4 else "****"
    logger.info(f"[BANK] Verifying Bank details IFSC: {ifsc}, Account: {masked_account}")
    result = call_setu_api(BANK_API_URL, payload, BANK_HEADERS)
    
    # The Setu API returns 'verification' field (not 'status')
    # Set status based on verification field
    if result.get('verification') == 'success':
        result['status'] = 'success'
        logger.info(f"[BANK] Account verified successfully: {result.get('message')}")
    else:
        logger.warning(f"[BANK] Verification failed: {result.get('message')}")
    
    # Save to database if verification successful
    if db_session and result.get('data'):
        try:
            user_email = session.get('user', 'unknown')
            bank_data = result.get('data', {})
            
            # Extract data from various possible field names
            holder_name = (
                bank_data.get('account_holder_name') or 
                bank_data.get('name') or 
                bank_data.get('accountHolderName') or
                'N/A'
            )
            bank_name = (
                bank_data.get('bank_name') or 
                bank_data.get('bankName') or 
                bank_data.get('bank') or
                'N/A'
            )
            branch = (
                bank_data.get('branch') or 
                bank_data.get('branch_name') or 
                bank_data.get('branchName') or
                'N/A'
            )
            
            bank_verification = BankVerification(
                user_email=user_email,
                account_number=account_number,
                ifsc_code=ifsc,
                account_holder_name=holder_name,
                bank_name=bank_name,
                branch_name=branch,
                status=result.get('status', 'unknown'),
                verification_data=result  # Store complete JSON
            )
            
            db_session.add(bank_verification)
            db_session.commit()
            logger.info(f"[DB] Bank verification saved for user: {user_email}")
            
            # Send completion emails
            try:
                # Get user's full name from PAN verification
                pan_verification = db_session.query(PANVerification).filter_by(user_email=user_email).first()
                user_name = pan_verification.full_name if pan_verification else user_email.split('@')[0]
                
                # Send email to user
                logger.info(f"[EMAIL] Sending completion email to user: {user_email}")
                user_email_result = send_completion_email_to_user(user_email, user_name)
                logger.info(f"[EMAIL] User email result: {user_email_result['message']}")
                
                # Send notification to company
                logger.info(f"[EMAIL] Sending completion notification to company")
                company_email_result = send_completion_email_to_company(user_email, user_name)
                logger.info(f"[EMAIL] Company email result: {company_email_result['message']}")
                
                # Create verification log
                logger.info(f"[VERIFICATION LOG] Creating completion log for user: {user_email}")
                
                # Check which verifications are completed
                aadhaar_verification = db_session.query(AadhaarVerification).filter_by(user_email=user_email).first()
                document_verification = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
                
                verification_log = VerificationLog(
                    user_email=user_email,
                    verification_status='completed',
                    pan_verified=bool(pan_verification),
                    aadhaar_verified=bool(aadhaar_verification),
                    documents_verified=bool(document_verification and document_verification.status == 'complete'),
                    bank_verified=True,
                    verification_completed_at=datetime.utcnow(),
                    emails_sent=True,
                    user_email_sent=(user_email_result.get('status') == 200),
                    company_email_sent=(company_email_result.get('status') == 200),
                    notes=f"Verification completed successfully. User: {user_name}"
                )
                
                db_session.add(verification_log)
                db_session.commit()
                logger.info(f"[VERIFICATION LOG] Log saved successfully for user: {user_email}")
                
                # Add email status to result
                result['emails_sent'] = True
                result['congratulations'] = True
                
            except Exception as e:
                logger.error(f"[EMAIL] Failed to send completion emails: {e}")
                result['emails_sent'] = False
                
        except Exception as e:
            logger.error(f"[DB] Failed to save Bank verification: {e}")
            db_session.rollback()
    
    return jsonify(result)


@app.route('/digilocker/create-request', methods=['GET', 'POST'])
@login_required
def create_digilocker_request():
    user_email = session.get('user')
    if not user_email:
        return redirect(url_for('login'))
    
    payload = {
        "redirectUrl": REDIRECT_URL,
        "consent": "Y",
        "types": [
            "PAN_CARD", 
            "AADHAAR", 
            "DL",
            "SSCMRK",   # 10th Marksheet
            "HSCMRK",   # 12th Marksheet
            "DIGCER",   # Degree Certificate
            "PGCER",    # Post Graduate Certificate
            "DIGMRK"    # Degree Marksheet
        ] 
    }

    logger.info(f"[DL] Creating DigiLocker request for user: {user_email}")
    logger.info(f"[DL] Request payload: {payload}")
    
    try:
        response = requests.post(
            DIGILOCKER_BASE_URL,
            json=payload,
            headers=DIGILOCKER_HEADERS,
            timeout=10
        )
        response.raise_for_status()
        res = response.json()

        request_id = res.get("id")
        login_url = res.get("url")

        if not request_id or not login_url:
            logger.error(f"[DL] Invalid create-request response: {res}")
            abort(500, "Invalid DigiLocker request response")

        # Store the request_id to user_email mapping for callback restoration
        # Use a simple in-memory dict (in production, use Redis or database)
        if 'digilocker_requests' not in app.config:
            app.config['digilocker_requests'] = {}
        app.config['digilocker_requests'][request_id] = user_email
        logger.info(f"[DL] Stored mapping: request_id={request_id} -> user={user_email}")

        logger.info(f"[DL] Redirecting user to DigiLocker: {login_url}")
        return redirect(login_url)

    except Exception as e:
        logger.error(f"[DL] Error creating request: {e}")
        abort(500, "Failed to create DigiLocker request")



@app.route('/digilocker/callback')
def digilocker_callback():
    # Note: No @login_required here because user might be redirected from external DigiLocker site
    # We'll check session and redirect to login if needed, but preserve the callback parameters
    
    request_id = request.args.get("id")
    success = request.args.get("success")
    scope = request.args.get("scope", "")  # Get consented document types
    
    success_bool = success and success.lower() == "true"

    logger.info(f"[DL CALLBACK] request_id={request_id}, success={success}, scope={scope}")
    logger.info(f"[DL CALLBACK] Current session keys: {list(session.keys())}")
    logger.info(f"[DL CALLBACK] User in session: {'user' in session}")

    if not request_id:
        abort(400, "Missing request ID")

    # Check if user is logged in, if not, try to restore from request_id or redirect to login
    if 'user' not in session:
        logger.warning(f"[DL CALLBACK] User not logged in, attempting to restore session")
        
        # Try to restore user from request_id mapping
        restored_user = None
        if 'digilocker_requests' in app.config and request_id in app.config['digilocker_requests']:
            restored_user = app.config['digilocker_requests'][request_id]
            logger.info(f"[DL CALLBACK] Found user mapping: request_id={request_id} -> user={restored_user}")
            
            # Restore session
            session['user'] = restored_user
            session['user_name'] = restored_user.split('@')[0].capitalize()
            session['consent_given'] = True  # Skip consent since they're coming from DigiLocker
            session.modified = True
            logger.info(f"[DL CALLBACK] Session restored for user: {restored_user}")
            
            # Clean up the mapping
            del app.config['digilocker_requests'][request_id]
        else:
            logger.error(f"[DL CALLBACK] No user mapping found for request_id: {request_id}")
            # Store callback data for after login
            session['pending_digilocker_callback'] = {
                'request_id': request_id,
                'success': success,
                'scope': scope
            }
            session.modified = True
            logger.info(f"[DL CALLBACK] Stored pending callback data in session, redirecting to login")
            flash('Please login to complete your DigiLocker verification', 'info')
            return redirect(url_for('login'))

    if not success_bool:
        msg = request.args.get("errMessage", "User denied permission")
        logger.error(f"[DL CALLBACK] User failed login: {msg}")
        session['digilocker_error'] = msg
        return redirect(url_for('aadhaar_verification'))

    # Parse and store the consented scope
    # Scope comes as "ADHAR+PANCR+DRVLC" format
    consented_docs = []
    if scope:
        # Split by + and decode URL encoding
        from urllib.parse import unquote
        scope_decoded = unquote(scope)
        consented_docs = [doc.strip() for doc in scope_decoded.split('+') if doc.strip()]
        logger.info(f"[DL CALLBACK] Parsed consented documents: {consented_docs}")
    
    # Store the request ID and scope in session
    session['digilocker_request_id'] = request_id
    session['digilocker_success'] = True
    session['digilocker_scope'] = consented_docs
    session.modified = True
    
    logger.info(f"[DL CALLBACK] Login successful, user={session.get('user')}, consented to {len(consented_docs)} document types")
    logger.info(f"[DL CALLBACK] Session data stored, redirecting to aadhaar_verification")
    return redirect(url_for('aadhaar_verification'))


@app.route('/digilocker/request-status', methods=['POST'])
@login_required
def get_digilocker_request_status() -> Any:
    data: Dict[str, Any] = request.json or {}
    request_id: Optional[str] = data.get('id')

    if not request_id:
        abort(400, description="Request ID is required")

    status_url = f"{DIGILOCKER_BASE_URL}/{request_id}/status"
    logger.info(f"[DL] Checking status: {status_url}")

    try:
        status_res = requests.get(status_url, headers=DIGILOCKER_HEADERS, timeout=10)
        status_res.raise_for_status()
        status_data = status_res.json()

        normalized = {
            "id": status_data.get("id"),
            "status": status_data.get("status"),
            "url": status_data.get("url"),
            "validUpto": status_data.get("validUpto"),
            "traceId": status_data.get("traceId"),
            "userDetails": status_data.get("digilockerUserDetails", {}),
            "documents": [],
            "aadhaar": None  
        }

        logger.info(f"[DL] Normalized status: {normalized}")

       
        if status_data.get("status") != "authenticated":
            return jsonify(normalized)

        try:
            aadhaar_url = f"{DIGILOCKER_BASE_URL}/{request_id}/aadhaar"
            logger.info(f"[DL] Fetching Aadhaar XML: {aadhaar_url}")

            aadhaar_res = requests.get(aadhaar_url, headers=DIGILOCKER_HEADERS, timeout=15)

            if aadhaar_res.status_code == 200:
                aadhaar_raw = aadhaar_res.json()
                logger.info(f"[DL] ========== AADHAAR RAW RESPONSE ==========")
                logger.info(f"[DL] Response keys: {list(aadhaar_raw.keys())}")
                logger.info(f"[DL] Full response: {aadhaar_raw}")
                
                # Parse XML if present - check multiple possible locations
                xml_string = None
                xml_file_url = None
                
                # Try different paths where XML might be
                if isinstance(aadhaar_raw, dict):
                    # Check for nested aadhaar.xml.fileUrl structure (Setu API format)
                    if aadhaar_raw.get('aadhaar') and isinstance(aadhaar_raw['aadhaar'], dict):
                        xml_obj = aadhaar_raw['aadhaar'].get('xml')
                        if isinstance(xml_obj, dict):
                            xml_file_url = xml_obj.get('fileUrl')
                            logger.info(f"[DL] Found XML fileUrl: {xml_file_url}")
                    
                    # Also check for direct XML string
                    xml_string = (
                        aadhaar_raw.get('xml') or 
                        aadhaar_raw.get('data') or
                        aadhaar_raw.get('aadhaarXml') or
                        aadhaar_raw.get('content')
                    )
                
                logger.info(f"[DL] XML string found: {bool(xml_string)}, XML URL found: {bool(xml_file_url)}")
                
                # Download XML file if URL is available
                if xml_file_url:
                    logger.info(f"[DL] Downloading Aadhaar XML from: {xml_file_url}")
                    try:
                        xml_response = requests.get(xml_file_url, timeout=30)
                        if xml_response.status_code == 200:
                            xml_content = xml_response.content
                            logger.info(f"[DL] Downloaded Aadhaar XML, size: {len(xml_content)} bytes")
                            
                            # Save XML file
                            user_email = session.get('user', 'unknown')
                            safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            
                            # Try S3 upload
                            if s3_client and S3_BUCKET_NAME:
                                try:
                                    s3_key = f"{safe_email}/digilocker/AADHAAR_{timestamp}.xml"
                                    s3_client.put_object(
                                        Bucket=S3_BUCKET_NAME,
                                        Key=s3_key,
                                        Body=xml_content,
                                        ContentType='application/xml',
                                        Metadata={
                                            'user_email': user_email,
                                            'document_type': 'AADHAAR_XML',
                                            'source': 'digilocker'
                                        }
                                    )
                                    s3_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                                    aadhaar_raw['xml_s3_url'] = s3_url
                                    aadhaar_raw['xml_s3_key'] = s3_key
                                    logger.info(f"[S3] Uploaded Aadhaar XML to S3: {s3_key}")
                                except Exception as e:
                                    logger.error(f"[S3] Failed to upload Aadhaar XML: {e}")
                            
                            # Fallback to local storage
                            if not aadhaar_raw.get('xml_s3_url'):
                                local_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'digilocker')
                                os.makedirs(local_dir, exist_ok=True)
                                local_filename = f"AADHAAR_{timestamp}.xml"
                                local_path = os.path.join(local_dir, local_filename)
                                
                                with open(local_path, 'wb') as f:
                                    f.write(xml_content)
                                
                                aadhaar_raw['xml_local_url'] = f"/uploads/{safe_email}/digilocker/{local_filename}"
                                logger.info(f"[LOCAL] Saved Aadhaar XML locally: {local_path}")
                            
                            # Also store XML as string for parsing
                            xml_string = xml_content.decode('utf-8')
                        else:
                            logger.warning(f"[DL] Failed to download Aadhaar XML: {xml_response.status_code}")
                    except Exception as e:
                        logger.error(f"[DL] Error downloading/uploading Aadhaar XML: {e}")
                
                # Check if there's a PDF link in the response - check multiple possible keys
                aadhaar_pdf_link = None
                possible_link_keys = ['link', 'url', 'documentLink', 'pdfLink', 'fileUrl', 'downloadUrl', 'digilockerUrl', 'file']
                if isinstance(aadhaar_raw, dict):
                    for key in possible_link_keys:
                        if aadhaar_raw.get(key):
                            aadhaar_pdf_link = aadhaar_raw.get(key)
                            logger.info(f"[DL] Found Aadhaar PDF link in '{key}': {aadhaar_pdf_link}")
                            break
                
                if not aadhaar_pdf_link:
                    logger.warning(f"[DL] No Aadhaar PDF link found. Checked keys: {possible_link_keys}")
                
                # Download and upload Aadhaar PDF to S3 if link available
                if aadhaar_pdf_link:
                    logger.info(f"[DL] Found Aadhaar PDF link: {aadhaar_pdf_link}")
                    try:
                        pdf_response = requests.get(aadhaar_pdf_link, timeout=30)
                        if pdf_response.status_code == 200:
                            pdf_content = pdf_response.content
                            logger.info(f"[DL] Downloaded Aadhaar PDF, size: {len(pdf_content)} bytes")
                            
                            # Upload to S3
                            user_email = session.get('user', 'unknown')
                            safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
                            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                            s3_key = f"{safe_email}/digilocker/AADHAAR_{timestamp}.pdf"
                            
                            # Try S3 upload
                            if s3_client and S3_BUCKET_NAME:
                                try:
                                    s3_client.put_object(
                                        Bucket=S3_BUCKET_NAME,
                                        Key=s3_key,
                                        Body=pdf_content,
                                        ContentType='application/pdf',
                                        Metadata={
                                            'user_email': user_email,
                                            'document_type': 'AADHAAR',
                                            'source': 'digilocker'
                                        }
                                    )
                                    s3_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                                    aadhaar_raw['s3_url'] = s3_url
                                    aadhaar_raw['s3_key'] = s3_key
                                    logger.info(f"[S3] Uploaded Aadhaar PDF to S3: {s3_key}")
                                except Exception as e:
                                    logger.error(f"[S3] Failed to upload Aadhaar PDF: {e}")
                            
                            # Fallback to local storage
                            if not aadhaar_raw.get('s3_url'):
                                local_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'digilocker')
                                os.makedirs(local_dir, exist_ok=True)
                                local_filename = f"AADHAAR_{timestamp}.pdf"
                                local_path = os.path.join(local_dir, local_filename)
                                
                                with open(local_path, 'wb') as f:
                                    f.write(pdf_content)
                                
                                aadhaar_raw['local_url'] = f"/uploads/{safe_email}/digilocker/{local_filename}"
                                logger.info(f"[LOCAL] Saved Aadhaar PDF locally: {local_path}")
                        else:
                            logger.warning(f"[DL] Failed to download Aadhaar PDF: {pdf_response.status_code}")
                    except Exception as e:
                        logger.error(f"[DL] Error downloading/uploading Aadhaar PDF: {e}")
                
                if xml_string and isinstance(xml_string, str):
                    try:
                        logger.info(f"[DL] Attempting to parse XML (length: {len(xml_string)})")
                        root = ET.fromstring(xml_string)
                        logger.info(f"[DL] XML root tag: {root.tag}, attribs: {root.attrib}")
                        
                        # Extract data from XML attributes
                        parsed_data = {
                            'name': root.get('name') or root.get('n') or '',
                            'dob': root.get('dob') or root.get('dateOfBirth') or '',
                            'gender': root.get('gender') or root.get('g') or '',
                            'uid': root.get('uid') or root.get('aadhaarNumber') or '',
                            'house': root.get('house') or root.get('h') or '',
                            'street': root.get('street') or root.get('s') or '',
                            'lm': root.get('lm') or '',
                            'loc': root.get('loc') or root.get('l') or '',
                            'vtc': root.get('vtc') or root.get('v') or '',
                            'subdist': root.get('subdist') or '',
                            'dist': root.get('dist') or root.get('d') or '',
                            'state': root.get('state') or root.get('st') or '',
                            'pc': root.get('pc') or root.get('pincode') or '',
                            'co': root.get('co') or root.get('c') or '',
                        }
                        
                        # Build complete address
                        address_parts = [p for p in [
                            parsed_data.get('house'),
                            parsed_data.get('street'),
                            parsed_data.get('lm'),
                            parsed_data.get('loc'),
                            parsed_data.get('vtc'),
                            parsed_data.get('subdist'),
                            parsed_data.get('dist'),
                            parsed_data.get('state'),
                            f"PIN: {parsed_data.get('pc')}" if parsed_data.get('pc') else None
                        ] if p]
                        
                        if address_parts:
                            parsed_data['address'] = ', '.join(address_parts)
                        
                        # Remove empty values
                        parsed_data = {k: v for k, v in parsed_data.items() if v}
                        
                        aadhaar_raw['data'] = parsed_data
                        logger.info(f"[DL] ✓ Successfully parsed Aadhaar data: {parsed_data}")
                    except ET.ParseError as e:
                        logger.error(f"[DL] ✗ Failed to parse Aadhaar XML: {e}")
                    except Exception as e:
                        logger.error(f"[DL] ✗ Error processing Aadhaar XML: {e}", exc_info=True)
                else:
                    logger.warning(f"[DL] No XML string found in response. Response type: {type(aadhaar_raw)}")
                    # If the response itself contains structured data, use it directly
                    if isinstance(aadhaar_raw, dict) and any(k in aadhaar_raw for k in ['name', 'uid', 'dob', 'gender']):
                        logger.info(f"[DL] Using response as structured data directly")
                        aadhaar_raw['data'] = aadhaar_raw
                
                normalized["aadhaar"] = aadhaar_raw
                logger.info(f"[DL] Final normalized aadhaar keys: {list(normalized['aadhaar'].keys()) if isinstance(normalized.get('aadhaar'), dict) else 'not a dict'}")
            else:
                logger.warning(f"[DL] Aadhaar fetch failed: {aadhaar_res.text}")

        except Exception as e:
            logger.error(f"[DL] Aadhaar fetch error: {e}")

        # Get consented documents from session (stored during callback)
        # The status API doesn't return the scope, it was in the callback URL
        consented_documents = session.get('digilocker_scope', [])
        logger.info(f"[DL] User consented scope from session: {consented_documents}")
        
        # If not in session, try to get from status_data (some APIs might return it)
        if not consented_documents:
            consented_documents = status_data.get("scope", [])
            logger.info(f"[DL] Using scope from API response: {consented_documents}")

        if consented_documents:
            # Map common document type codes to API docTypes
            doc_type_mapping = {
                'ADHAR': 'AADHAAR',
                'PANCR': 'PAN_CARD', 
                'DRVLC': 'DL',
                'SSCMRK': 'SSCMRK',
                'HSCMRK': 'HSCMRK',
                'DIGCER': 'DIGCER',
                'DIGMRK': 'DIGMRK',
                'PGCER': 'PGCER',
                'PGMRK': 'PGMRK'
            }
            
            # Fetch catalog to get document details
            catalog_url = f"{DIGILOCKER_BASE_URL}/documents"
            catalog_res = requests.get(catalog_url, headers=DIGILOCKER_HEADERS, timeout=10)
            catalog_res.raise_for_status()

            catalog_list = catalog_res.json().get("documents", [])
            logger.info(f"[DL] Catalog loaded: {len(catalog_list)} documents")

            # Match consented documents with catalog
            user_doc_defs = []
            for consented_code in consented_documents:
                # Map the consented code to API docType
                api_doc_type = doc_type_mapping.get(consented_code, consented_code)
                
                # Find matching document in catalog
                for d in catalog_list:
                    catalog_doc_type = (
                        d.get("docType") or
                        d.get("documentType") or
                        d.get("documentIdentifier")
                    )
                    # Check both the original code and mapped type
                    if catalog_doc_type == api_doc_type or catalog_doc_type == consented_code:
                        d["docType"] = catalog_doc_type
                        user_doc_defs.append(d)
                        logger.info(f"[DL] Matched consented '{consented_code}' to catalog '{catalog_doc_type}'")
                        break
            
            logger.info(f"[DL] Found {len(user_doc_defs)} documents to fetch")

            fetched_docs = []

            for doc_def in user_doc_defs:
                doc_type = doc_def["docType"]
                
                # Prepare parameters - get user data from session/database
                params = {}
                user_email = session.get('user', 'unknown')
                
                # For PAN Card - get from database
                if doc_type == 'PANCR' and db_session:
                    try:
                        pan_verification = db_session.query(PANVerification).filter_by(
                            user_email=user_email
                        ).order_by(PANVerification.created_at.desc()).first()
                        
                        if pan_verification:
                            params = {
                                "panno": pan_verification.pan_number,
                                "PANFullName": pan_verification.full_name
                            }
                            logger.info(f"[DL] Using PAN data: {pan_verification.pan_number}")
                    except Exception as e:
                        logger.error(f"[DL] Failed to get PAN data: {e}")
                
                # For Driving License - try without parameters (DigiLocker might have it stored)
                elif doc_type == 'DRVLC':
                    logger.info(f"[DL] Attempting to fetch DL from DigiLocker storage")
                    # Try without parameters first - user might have it stored in DigiLocker
                    params = {}
                
                payload = {
                    "docType": doc_type,
                    "orgId": doc_def.get("orgId"),
                    "format": "json",  # Use JSON to get structured data instead of PDF
                    "consent": "Y"
                }
                
                # Only add parameters if we have them
                if params:
                    payload["parameters"] = params

                fetch_url = f"{DIGILOCKER_BASE_URL}/{request_id}/document"
                logger.info(f"[DL] Fetching {doc_type} document with payload: {payload}")

                try:
                    fetch_res = requests.post(
                        fetch_url, json=payload, headers=DIGILOCKER_HEADERS, timeout=20
                    )
                    
                    logger.info(f"[DL] {doc_type} fetch status: {fetch_res.status_code}")
                    
                    if fetch_res.status_code == 200:
                        doc_data = fetch_res.json()
                        logger.info(f"[DL] {doc_type} response keys: {list(doc_data.keys()) if isinstance(doc_data, dict) else 'not a dict'}")
                        logger.info(f"[DL] {doc_type} full response: {doc_data}")
                        
                        # Add document type info
                        doc_data['_docType'] = doc_type
                        doc_data['_docName'] = doc_def.get('name', doc_type)
                        
                        # Check for PDF link in various possible keys
                        pdf_link = None
                        possible_link_keys = ['link', 'url', 'documentLink', 'pdfLink', 'fileUrl', 'downloadUrl', 'digilockerUrl']
                        for key in possible_link_keys:
                            if doc_data.get(key):
                                pdf_link = doc_data.get(key)
                                logger.info(f"[DL] Found PDF link in '{key}' for {doc_type}: {pdf_link}")
                                break
                        
                        # For PAN Card - check if we have data instead of fileUrl
                        if doc_type == 'PANCR' and not pdf_link and doc_data.get('data'):
                            logger.info(f"[DL] PAN Card has JSON data, attempting to fetch PDF version...")
                            # Try to get PDF version of PAN
                            try:
                                pdf_payload = payload.copy()
                                pdf_payload['format'] = 'pdf'
                                pdf_fetch_res = requests.post(
                                    fetch_url, json=pdf_payload, headers=DIGILOCKER_HEADERS, timeout=20
                                )
                                if pdf_fetch_res.status_code == 200:
                                    pdf_json = pdf_fetch_res.json()
                                    logger.info(f"[DL] PAN PDF response keys: {list(pdf_json.keys()) if isinstance(pdf_json, dict) else 'not a dict'}")
                                    for key in possible_link_keys:
                                        if pdf_json.get(key):
                                            pdf_link = pdf_json.get(key)
                                            logger.info(f"[DL] Found PAN PDF link in '{key}': {pdf_link}")
                                            break
                            except Exception as e:
                                logger.error(f"[DL] Error fetching PAN PDF: {e}")
                        
                        # If no link found in JSON response, try fetching as PDF format
                        if not pdf_link and doc_type != 'PANCR':  # Already tried for PAN above
                            logger.warning(f"[DL] No PDF link found in JSON response for {doc_type}, trying PDF format...")
                            try:
                                pdf_payload = payload.copy()
                                pdf_payload['format'] = 'pdf'
                                pdf_fetch_res = requests.post(
                                    fetch_url, json=pdf_payload, headers=DIGILOCKER_HEADERS, timeout=20
                                )
                                if pdf_fetch_res.status_code == 200:
                                    # Check if response is actual PDF content
                                    content_type = pdf_fetch_res.headers.get('Content-Type', '')
                                    logger.info(f"[DL] PDF format response Content-Type: {content_type}")
                                    if 'application/pdf' in content_type or pdf_fetch_res.content[:4] == b'%PDF':
                                        logger.info(f"[DL] Received PDF content directly for {doc_type}")
                                        pdf_content = pdf_fetch_res.content
                                        
                                        # Save PDF directly
                                        user_email = session.get('user', 'unknown')
                                        safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
                                        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                        
                                        if s3_client and S3_BUCKET_NAME:
                                            try:
                                                s3_key = f"{safe_email}/digilocker/{doc_type}_{timestamp}.pdf"
                                                s3_client.put_object(
                                                    Bucket=S3_BUCKET_NAME,
                                                    Key=s3_key,
                                                    Body=pdf_content,
                                                    ContentType='application/pdf',
                                                    Metadata={
                                                        'user_email': user_email,
                                                        'document_type': doc_type,
                                                        'source': 'digilocker'
                                                    }
                                                )
                                                doc_data['s3_url'] = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                                                doc_data['s3_key'] = s3_key
                                                logger.info(f"[S3] Uploaded {doc_type} PDF to S3: {s3_key}")
                                            except Exception as e:
                                                logger.error(f"[S3] Failed to upload {doc_type} PDF: {e}")
                                        
                                        if not doc_data.get('s3_url'):
                                            local_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'digilocker')
                                            os.makedirs(local_dir, exist_ok=True)
                                            local_filename = f"{doc_type}_{timestamp}.pdf"
                                            local_path = os.path.join(local_dir, local_filename)
                                            
                                            with open(local_path, 'wb') as f:
                                                f.write(pdf_content)
                                            
                                            doc_data['local_url'] = f"/uploads/{safe_email}/digilocker/{local_filename}"
                                            logger.info(f"[LOCAL] Saved {doc_type} PDF locally: {local_path}")
                                    else:
                                        # Might be JSON with link
                                        try:
                                            pdf_json = pdf_fetch_res.json()
                                            for key in possible_link_keys:
                                                if pdf_json.get(key):
                                                    pdf_link = pdf_json.get(key)
                                                    logger.info(f"[DL] Found PDF link in PDF format response '{key}': {pdf_link}")
                                                    break
                                        except:
                                            pass
                            except Exception as e:
                                logger.error(f"[DL] Error fetching PDF format for {doc_type}: {e}")
                        
                        # Download and upload PDF to S3 if document link is available
                        if pdf_link:
                            logger.info(f"[DL] Downloading PDF from link for {doc_type}: {pdf_link}")
                            
                            try:
                                # Download PDF from DigiLocker link
                                pdf_response = requests.get(pdf_link, timeout=30)
                                if pdf_response.status_code == 200:
                                    pdf_content = pdf_response.content
                                    logger.info(f"[DL] Downloaded PDF for {doc_type}, size: {len(pdf_content)} bytes")
                                    
                                    # Verify it's actually a PDF
                                    if pdf_content[:4] != b'%PDF':
                                        logger.warning(f"[DL] Downloaded content doesn't appear to be a PDF for {doc_type}")
                                        logger.warning(f"[DL] Content preview: {pdf_content[:100]}")
                                        # Continue anyway, might still be valid
                                    
                                    # Upload to S3
                                    user_email = session.get('user', 'unknown')
                                    safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
                                    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                                    s3_key = f"{safe_email}/digilocker/{doc_type}_{timestamp}.pdf"
                                    
                                    s3_url = None
                                    
                                    # Try S3 upload
                                    if s3_client and S3_BUCKET_NAME:
                                        try:
                                            s3_client.put_object(
                                                Bucket=S3_BUCKET_NAME,
                                                Key=s3_key,
                                                Body=pdf_content,
                                                ContentType='application/pdf',
                                                Metadata={
                                                    'user_email': user_email,
                                                    'document_type': doc_type,
                                                    'source': 'digilocker'
                                                }
                                            )
                                            s3_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                                            logger.info(f"[S3] Uploaded {doc_type} PDF to S3: {s3_key}")
                                            doc_data['s3_url'] = s3_url
                                            doc_data['s3_key'] = s3_key
                                        except Exception as e:
                                            logger.error(f"[S3] Failed to upload {doc_type} PDF: {e}")
                                    
                                    # Fallback to local storage
                                    if not s3_url:
                                        local_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'digilocker')
                                        os.makedirs(local_dir, exist_ok=True)
                                        local_filename = f"{doc_type}_{timestamp}.pdf"
                                        local_path = os.path.join(local_dir, local_filename)
                                        
                                        with open(local_path, 'wb') as f:
                                            f.write(pdf_content)
                                        
                                        doc_data['local_url'] = f"/uploads/{safe_email}/digilocker/{local_filename}"
                                        logger.info(f"[LOCAL] Saved {doc_type} PDF locally: {local_path}")
                                        
                                else:
                                    logger.warning(f"[DL] Failed to download PDF for {doc_type}: {pdf_response.status_code}")
                            except Exception as e:
                                logger.error(f"[DL] Error downloading/uploading PDF for {doc_type}: {e}")
                        
                        fetched_docs.append(doc_data)
                        logger.info(f"[DL] ✓ Successfully fetched {doc_type}")
                    else:
                        logger.warning(f"[DL] {doc_type} fetch failed ({fetch_res.status_code}): {fetch_res.text}")
                        
                except Exception as e:
                    logger.error(f"[DL] Error fetching {doc_type}: {e}")

            normalized["documents"] = fetched_docs
            logger.info(f"[DL] Total documents fetched: {len(fetched_docs)}")

        # Save Aadhaar verification to database
        if db_session and normalized.get("aadhaar"):
            try:
                user_email = session.get('user', 'unknown')
                aadhaar_info = normalized.get("aadhaar", {})
                
                # Handle nested aadhaar.aadhaar structure
                if isinstance(aadhaar_info, dict) and 'aadhaar' in aadhaar_info:
                    aadhaar_details = aadhaar_info['aadhaar']
                else:
                    aadhaar_details = aadhaar_info
                
                # Extract data for easy querying
                name = aadhaar_details.get('name', '')
                dob = aadhaar_details.get('dateOfBirth') or aadhaar_details.get('dob', '')
                gender = aadhaar_details.get('gender', '')
                masked_number = aadhaar_details.get('maskedNumber', '')
                
                # Build address
                address = ''
                if aadhaar_details.get('address'):
                    addr = aadhaar_details['address']
                    if isinstance(addr, dict):
                        address_parts = [
                            addr.get('careOf'),
                            addr.get('house'),
                            addr.get('street'),
                            addr.get('locality'),
                            addr.get('vtc'),
                            addr.get('district'),
                            addr.get('state'),
                            f"PIN: {addr.get('pin')}" if addr.get('pin') else None
                        ]
                        address = ', '.join([p for p in address_parts if p])
                
                aadhaar_verification = AadhaarVerification(
                    user_email=user_email,
                    full_name=name,
                    date_of_birth=dob,
                    gender=gender,
                    masked_number=masked_number,
                    address=address,
                    verification_method='digilocker',
                    digilocker_request_id=request_id,
                    verification_data=normalized  # Store complete JSON response including nested aadhaar.aadhaar
                )
                
                db_session.add(aadhaar_verification)
                db_session.commit()
                logger.info(f"[DB] Complete Aadhaar JSON saved for user: {user_email}")
            except Exception as e:
                logger.error(f"[DB] Failed to save Aadhaar verification: {e}")
                db_session.rollback()

        return jsonify(normalized)

    except Exception as e:
        logger.error(f"[DL] Status error: {e}")
        abort(500, description="DigiLocker API failure")



@app.route('/digilocker/fetch-all-documents', methods=['POST'])
@login_required
def fetch_all_documents():
    data = request.json or {}
    request_id = data.get('id')
    documents = data.get('documents')

    if not request_id or not documents:
        abort(400, "Request ID and documents list are required")

    logger.info(f"[DL] Fetching {len(documents)} documents for request ID: {request_id}")

    all_docs = []

    for doc in documents:
        
        doc_type = doc.get("type") or doc.get("documentIdentifier")
        doc_name = doc.get("name") or doc.get("description")

        if not doc_type:
            continue

        payload = {
            "id": request_id,
            "type": doc_type
        }

        logger.info(f"[DL] Fetching document type: {doc_type}")
        logger.info(f"[DL] Document URL: {DIGILOCKER_BASE_URL}/document")
        logger.info(f"[DL] Document Payload: {payload}")

        try:
            response = requests.post(
                f"{DIGILOCKER_BASE_URL}/document",
                json=payload,
                headers=DIGILOCKER_HEADERS,
                timeout=10
            )
            logger.info(f"[DL] Document fetch response for {doc_type}: Status {response.status_code}")
            logger.info(f"[DL] Document response body: {response.text}")
            response.raise_for_status()

            doc_data = response.json()
            all_docs.append({
                "type": doc_type,
                "name": doc_name,
                "data": doc_data
            })

        except Exception as e:
            logger.error(f"[DL] Error fetching document {doc_type}: {e}")
            if hasattr(e, 'response') and e.response is not None:
                logger.error(f"[DL] Document error response: {e.response.text}")
           
            continue

    return jsonify(all_docs)


# =====================================================
# DIGILOCKER - Following Setu's 3-Step Flow
# =====================================================

@app.route('/digilocker/list-documents', methods=['POST'])
@login_required
def list_digilocker_documents():
    """
    Step 2: Get List of all docs available after user completes consent
    Call this after user completes the DigiLocker consent journey
    """
    data = request.json or {}
    request_id = data.get('requestId')
    
    if not request_id:
        abort(400, description="Request ID is required")
    
    logger.info(f"[DL LIST] Fetching document list for request ID: {request_id}")
    
    try:
        # Get the request status to check if authenticated
        status_url = f"{DIGILOCKER_BASE_URL}/{request_id}/status"
        status_res = requests.get(status_url, headers=DIGILOCKER_HEADERS, timeout=10)
        status_res.raise_for_status()
        status_data = status_res.json()
        
        if status_data.get("status") != "authenticated":
            return jsonify({
                'success': False,
                'message': 'User has not completed authentication',
                'status': status_data.get("status")
            }), 400
        
        # Get the list of documents user consented to
        consented_documents = status_data.get("scope", [])
        logger.info(f"[DL LIST] User consented to: {consented_documents}")
        
        if not consented_documents:
            return jsonify({
                'success': False,
                'message': 'No documents consented by user',
                'documents': []
            })
        
        # Fetch the document catalog
        catalog_url = f"{DIGILOCKER_BASE_URL}/documents"
        catalog_res = requests.get(catalog_url, headers=DIGILOCKER_HEADERS, timeout=10)
        catalog_res.raise_for_status()
        
        all_documents = catalog_res.json().get("documents", [])
        logger.info(f"[DL LIST] Total documents in catalog: {len(all_documents)}")
        
        # Filter to only show documents user has access to
        available_documents = []
        for doc in all_documents:
            doc_type = doc.get("docType") or doc.get("documentType") or doc.get("documentIdentifier")
            if doc_type in consented_documents:
                available_documents.append({
                    'docType': doc_type,
                    'name': doc.get('name') or doc.get('description', doc_type),
                    'orgId': doc.get('orgId'),
                    'parameters': doc.get('parameters', {}),
                    'description': doc.get('description', '')
                })
        
        logger.info(f"[DL LIST] Available documents: {len(available_documents)}")
        
        return jsonify({
            'success': True,
            'requestId': request_id,
            'status': status_data.get("status"),
            'documents': available_documents,
            'documentCount': len(available_documents)
        })
        
    except requests.exceptions.RequestException as e:
        logger.error(f"[DL LIST] API error: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to fetch document list',
            'error': str(e)
        }), 500


@app.route('/digilocker/fetch-document', methods=['POST'])
@login_required
def fetch_digilocker_document():
    """
    Step 3: Fetch a specific document by docType
    Supports PDF and JSON formats
    """
    data = request.json or {}
    request_id = data.get('requestId')
    doc_type = data.get('docType')
    doc_format = data.get('format', 'pdf').lower()  # pdf or json
    org_id = data.get('orgId')
    parameters = data.get('parameters', {})
    
    if not request_id or not doc_type:
        abort(400, description="Request ID and docType are required")
    
    if doc_format not in ['pdf', 'json']:
        abort(400, description="Format must be 'pdf' or 'json'")
    
    logger.info(f"[DL FETCH] Fetching document - Type: {doc_type}, Format: {doc_format}")
    
    try:
        # Prepare payload for document fetch
        payload = {
            "docType": doc_type,
            "format": doc_format,
            "consent": "Y"
        }
        
        if org_id:
            payload["orgId"] = org_id
        
        if parameters:
            payload["parameters"] = parameters
        
        # Fetch the document
        fetch_url = f"{DIGILOCKER_BASE_URL}/{request_id}/document"
        logger.info(f"[DL FETCH] POST {fetch_url}")
        logger.info(f"[DL FETCH] Payload: {payload}")
        
        fetch_res = requests.post(
            fetch_url,
            json=payload,
            headers=DIGILOCKER_HEADERS,
            timeout=30
        )
        
        logger.info(f"[DL FETCH] Response status: {fetch_res.status_code}")
        
        fetch_res.raise_for_status()
        doc_data = fetch_res.json()
        
        # Extract useful information from response
        result = {
            'success': True,
            'docType': doc_type,
            'format': doc_format,
            'data': doc_data
        }
        
        # If PDF, the response typically contains a base64 encoded file or URL
        if doc_format == 'pdf':
            if 'file' in doc_data:
                result['fileData'] = doc_data['file']
            if 'url' in doc_data:
                result['fileUrl'] = doc_data['url']
        
        # If JSON, extract structured data
        elif doc_format == 'json':
            result['structuredData'] = doc_data
        
        logger.info(f"[DL FETCH] Successfully fetched {doc_type}")
        
        # Optionally save to database
        if db_session:
            try:
                user_email = session.get('user', 'unknown')
                # You can create a DigiLockerDocument model to store fetched documents
                # For now, just log
                logger.info(f"[DL FETCH] Document fetched for user: {user_email}")
            except Exception as e:
                logger.error(f"[DB] Failed to log document fetch: {e}")
        
        return jsonify(result)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"[DL FETCH] API error: {e}")
        if hasattr(e, 'response') and e.response is not None:
            logger.error(f"[DL FETCH] Error response: {e.response.text}")
        
        return jsonify({
            'success': False,
            'message': f'Failed to fetch document: {doc_type}',
            'error': str(e)
        }), 500


@app.route('/digilocker/fetch-multiple', methods=['POST'])
@login_required
def fetch_multiple_documents():
    """
    Convenience endpoint to fetch multiple documents at once
    """
    data = request.json or {}
    request_id = data.get('requestId')
    doc_types = data.get('docTypes', [])  # List of docType strings
    doc_format = data.get('format', 'pdf')
    
    if not request_id or not doc_types:
        abort(400, description="Request ID and docTypes array are required")
    
    logger.info(f"[DL MULTI] Fetching {len(doc_types)} documents")
    
    results = []
    errors = []
    
    for doc_type in doc_types:
        try:
            payload = {
                "docType": doc_type,
                "format": doc_format,
                "consent": "Y"
            }
            
            fetch_url = f"{DIGILOCKER_BASE_URL}/{request_id}/document"
            fetch_res = requests.post(
                fetch_url,
                json=payload,
                headers=DIGILOCKER_HEADERS,
                timeout=30
            )
            
            if fetch_res.status_code == 200:
                doc_data = fetch_res.json()
                results.append({
                    'docType': doc_type,
                    'success': True,
                    'data': doc_data
                })
                logger.info(f"[DL MULTI] ✓ Fetched {doc_type}")
            else:
                errors.append({
                    'docType': doc_type,
                    'error': fetch_res.text
                })
                logger.warning(f"[DL MULTI] ✗ Failed to fetch {doc_type}: {fetch_res.status_code}")
                
        except Exception as e:
            errors.append({
                'docType': doc_type,
                'error': str(e)
            })
            logger.error(f"[DL MULTI] ✗ Error fetching {doc_type}: {e}")
    
    return jsonify({
        'success': len(errors) == 0,
        'requestId': request_id,
        'fetched': len(results),
        'failed': len(errors),
        'results': results,
        'errors': errors
    })


@app.route('/digilocker/fetch-marksheets', methods=['POST'])
@login_required
def fetch_marksheets():
    """
    Dedicated endpoint to fetch all available marksheets
    Fetches 10th, 12th, Degree, and PG marksheets/certificates
    """
    data = request.json or {}
    request_id = data.get('requestId')
    doc_format = data.get('format', 'pdf')  # pdf or json
    
    if not request_id:
        abort(400, description="Request ID is required")
    
    # Common marksheet document types
    marksheet_types = [
        {"docType": "SSCMRK", "name": "10th Marksheet", "category": "Secondary"},
        {"docType": "HSCMRK", "name": "12th Marksheet", "category": "Higher Secondary"},
        {"docType": "DIGMRK", "name": "Degree Marksheet", "category": "Undergraduate"},
        {"docType": "DIGCER", "name": "Degree Certificate", "category": "Undergraduate"},
        {"docType": "PGCER", "name": "Post Graduate Certificate", "category": "Post Graduate"},
        {"docType": "PGMRK", "name": "Post Graduate Marksheet", "category": "Post Graduate"},
    ]
    
    logger.info(f"[MARKSHEET] Fetching marksheets for request ID: {request_id}")
    
    # First, check which documents are available
    try:
        status_url = f"{DIGILOCKER_BASE_URL}/{request_id}/status"
        status_res = requests.get(status_url, headers=DIGILOCKER_HEADERS, timeout=10)
        status_res.raise_for_status()
        status_data = status_res.json()
        
        if status_data.get("status") != "authenticated":
            return jsonify({
                'success': False,
                'message': 'User has not completed authentication',
                'status': status_data.get("status")
            }), 400
        
        consented_documents = status_data.get("scope", [])
        logger.info(f"[MARKSHEET] Consented documents: {consented_documents}")
        
    except Exception as e:
        logger.error(f"[MARKSHEET] Failed to check status: {e}")
        return jsonify({
            'success': False,
            'message': 'Failed to verify authentication status',
            'error': str(e)
        }), 500
    
    # Fetch marksheets
    fetched = []
    failed = []
    
    for marksheet in marksheet_types:
        doc_type = marksheet["docType"]
        
        # Only try to fetch if user consented to this document type
        if doc_type not in consented_documents:
            logger.info(f"[MARKSHEET] Skipping {doc_type} - not in consented scope")
            continue
        
        try:
            payload = {
                "docType": doc_type,
                "format": doc_format,
                "consent": "Y"
            }
            
            fetch_url = f"{DIGILOCKER_BASE_URL}/{request_id}/document"
            logger.info(f"[MARKSHEET] Fetching {marksheet['name']} ({doc_type})")
            
            fetch_res = requests.post(
                fetch_url,
                json=payload,
                headers=DIGILOCKER_HEADERS,
                timeout=30
            )
            
            if fetch_res.status_code == 200:
                doc_data = fetch_res.json()
                
                result = {
                    'docType': doc_type,
                    'name': marksheet['name'],
                    'category': marksheet['category'],
                    'format': doc_format,
                    'data': doc_data,
                    'success': True
                }
                
                # Extract file data if PDF
                if doc_format == 'pdf':
                    if 'file' in doc_data:
                        result['fileData'] = doc_data['file']
                    if 'url' in doc_data:
                        result['fileUrl'] = doc_data['url']
                
                fetched.append(result)
                logger.info(f"[MARKSHEET] ✓ Successfully fetched {marksheet['name']}")
                
                # Save to database
                if db_session:
                    try:
                        user_email = session.get('user', 'unknown')
                        
                        # Check if document verification record exists
                        doc_verification = db_session.query(DocumentVerification).filter_by(
                            user_email=user_email
                        ).first()
                        
                        if not doc_verification:
                            doc_verification = DocumentVerification(
                                user_email=user_email,
                                status='in_progress'
                            )
                            db_session.add(doc_verification)
                        
                        # Store marksheet data in a JSON field (you may need to add this column)
                        # For now, just log
                        logger.info(f"[DB] Marksheet fetched for user: {user_email} - {doc_type}")
                        
                    except Exception as e:
                        logger.error(f"[DB] Failed to save marksheet fetch: {e}")
            else:
                failed.append({
                    'docType': doc_type,
                    'name': marksheet['name'],
                    'error': f"HTTP {fetch_res.status_code}",
                    'message': fetch_res.text
                })
                logger.warning(f"[MARKSHEET] ✗ Failed to fetch {marksheet['name']}: {fetch_res.status_code}")
                
        except Exception as e:
            failed.append({
                'docType': doc_type,
                'name': marksheet['name'],
                'error': str(e)
            })
            logger.error(f"[MARKSHEET] ✗ Error fetching {marksheet['name']}: {e}")
    
    return jsonify({
        'success': len(fetched) > 0,
        'requestId': request_id,
        'format': doc_format,
        'totalFetched': len(fetched),
        'totalFailed': len(failed),
        'marksheets': fetched,
        'errors': failed,
        'message': f"Successfully fetched {len(fetched)} marksheet(s)"
    })


@app.route('/esign/initiate', methods=['POST'])
@login_required
def initiate_esign() -> Any:
    data = request.json or {}
    if not data:
        abort(400, description="Request payload required")

    logger.info(f"[ESIGN] Initiating eSign with data: {data}")

    try:
        response = requests.post(ESIGN_API_URL, json=data, headers=ESIGN_HEADERS, timeout=10)
        response.raise_for_status()
        esign_response = response.json()
        logger.info(f"[ESIGN] Response: {esign_response}")
        return jsonify(esign_response)
    except Exception as e:
        logger.error(f"[ESIGN] Error: {e}")
        abort(500, description="Error initiating eSign")


@app.route('/upload-aadhaar', methods=['POST'])
@login_required
def upload_aadhaar():
    """Handle manual Aadhaar card upload with OCR validation and save to S3"""
    try:
        if 'aadhaar_file' not in request.files:
            return jsonify({'success': False, 'message': 'No file uploaded'}), 400
        
        file = request.files['aadhaar_file']
        
        if file.filename == '':
            return jsonify({'success': False, 'message': 'No file selected'}), 400
        
        # Validate file type
        allowed_extensions = {'jpg', 'jpeg', 'png', 'pdf'}
        file_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        
        if file_ext not in allowed_extensions:
            return jsonify({'success': False, 'message': 'Invalid file type'}), 400
        
        # Read file content for OCR processing
        file.seek(0)
        file_content = file.read()
        
        # Process document with OCR to validate and extract information
        logger.info("[AADHAAR OCR] Starting document validation and extraction...")
        is_valid, ocr_result = validate_and_extract_aadhaar(file_content, file.filename)
        
        if not is_valid or not ocr_result.get('is_aadhaar'):
            error_msg = ocr_result.get('error', 'Document is not a valid Aadhaar card')
            logger.warning(f"[AADHAAR OCR] Validation failed: {error_msg}")
            return jsonify({
                'success': False, 
                'message': error_msg,
                'ocr_details': ocr_result
            }), 400
        
        # Extract OCR data
        aadhaar_number = ocr_result.get('aadhaar_number')
        full_name = ocr_result.get('name')
        dob = ocr_result.get('dob')
        gender = ocr_result.get('gender')
        
        # Mask sensitive data in logs
        masked_aadhaar = f"****-****-{aadhaar_number[-4:]}" if aadhaar_number and len(aadhaar_number) >= 4 else "****"
        logger.info(f"[AADHAAR OCR] Extracted - Number: {masked_aadhaar}, Name: {full_name}, DOB: {dob}, Gender: {gender}")
        
        # Get user email
        user_email = session.get('user', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate S3 key with email and document type
        
        safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
        s3_key = f"{safe_email}/documents/aadhaar_{timestamp}.{file_ext}"
        
        file_url = None
        storage_location = None
        
        # Try to upload to S3
        if s3_client and S3_BUCKET_NAME:
            try:
                # Determine content type
                content_type_map = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'pdf': 'application/pdf'
                }
                content_type = content_type_map.get(file_ext, 'application/octet-stream')
                
                # Prepare metadata (S3 metadata must be ASCII only)
                # Encode non-ASCII characters to avoid S3 metadata errors
             
                metadata = {
                    'user_email': user_email,
                    'document_type': 'aadhaar',
                    'upload_time': timestamp,
                    'ocr_extracted': 'true'
                }
                
                # Only add ASCII-safe metadata
                if aadhaar_number and aadhaar_number.isascii():
                    metadata['aadhaar_number'] = aadhaar_number
                if full_name:
                    # Base64 encode non-ASCII names for metadata
                    try:
                        if full_name.isascii():
                            metadata['full_name'] = full_name
                        else:
                            # Store base64 encoded for non-ASCII
                            encoded_name = base64.b64encode(full_name.encode('utf-8')).decode('ascii')
                            metadata['full_name_encoded'] = encoded_name
                    except:
                        pass
                
                # Upload to S3
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=file_content,
                    ContentType=content_type,
                    Metadata=metadata
                )
                
                # Generate S3 URL
                file_url = f"https://{S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
                storage_location = 's3'
                
                logger.info(f"[AADHAAR UPLOAD] File uploaded to S3: {s3_key} for user: {user_email}")
                
            except ClientError as e:
                logger.warning(f"[AADHAAR UPLOAD] S3 upload failed: {e}. Falling back to local storage.")
                storage_location = None
        
        # Fallback to local storage if S3 fails or not configured
        if not storage_location:
            try:
                # Create local uploads directory
                upload_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'documents')
                os.makedirs(upload_dir, exist_ok=True)
                
                local_filename = f"aadhaar_{timestamp}.{file_ext}"
                filepath = os.path.join(upload_dir, local_filename)
                
                # Save file locally
                with open(filepath, 'wb') as f:
                    f.write(file_content)
                
                file_url = f"/uploads/{safe_email}/documents/{local_filename}"
                storage_location = 'local'
                
                logger.info(f"[AADHAAR UPLOAD] File saved locally: {filepath}")
            except Exception as e:
                logger.error(f"[AADHAAR UPLOAD] Failed to save locally: {e}")
                return jsonify({'success': False, 'message': 'Failed to save file'}), 500
        
        # Save to session
        session['aadhaar_uploaded'] = True
        session['aadhaar_s3_key'] = s3_key
        session['aadhaar_s3_url'] = file_url
        session['aadhaar_upload_time'] = timestamp
        session['aadhaar_ocr_data'] = {
            'aadhaar_number': aadhaar_number,
            'name': full_name,
            'dob': dob,
            'gender': gender
        }
        
        # Save to database with OCR extracted data
        if db_session:
            try:
                aadhaar_verification = AadhaarVerification(
                    user_email=user_email,
                    aadhaar_number=aadhaar_number,
                    masked_number=f"XXXX-XXXX-{aadhaar_number[-4:]}" if aadhaar_number else None,
                    full_name=full_name,
                    date_of_birth=dob,
                    gender=gender,
                    verification_method='manual_upload',
                    s3_file_key=s3_key,
                    s3_file_url=file_url,
                    verification_data={
                        'upload_method': 'manual', 
                        'file_type': file_ext,
                        'storage_location': storage_location,
                        'ocr_extracted': True,
                        'aadhaar_number': aadhaar_number,
                        'name': full_name,
                        'dob': dob,
                        'gender': gender,
                        'raw_ocr_text': ocr_result.get('raw_text', '')[:500]  # Store first 500 chars
                    }
                )
                db_session.add(aadhaar_verification)
                db_session.commit()
                logger.info(f"[DB] Manual Aadhaar upload with OCR data saved for user: {user_email}")
            except Exception as e:
                logger.error(f"[DB] Failed to save manual Aadhaar upload: {e}")
                db_session.rollback()
        
        return jsonify({
            'success': True,
            'message': 'Aadhaar uploaded and validated successfully',
            's3_key': s3_key,
            'url': file_url,
            'storage_location': storage_location,
            'extracted_data': {
                'aadhaar_number': aadhaar_number,
                'name': full_name,
                'dob': dob,
                'gender': gender,
                'masked_number': f"XXXX-XXXX-{aadhaar_number[-4:]}" if aadhaar_number else None
            }
        })
        
    except Exception as e:
        logger.error(f"[AADHAAR UPLOAD] Error: {e}")
        return jsonify({'success': False, 'message': 'Upload failed'}), 500


@app.errorhandler(400)
def bad_request(e):
    return jsonify(error=str(e.description)), 400


@app.errorhandler(500)
def server_error(e):
    return jsonify(error=str(e.description)), 500


if __name__ == "__main__":
    # Pre-load OCR reader on startup to avoid delay on first upload
    logger.info("[STARTUP] Pre-loading EasyOCR models...")
    try:
        
        get_ocr_reader() 
        logger.info("[STARTUP] ✓ OCR models loaded successfully")
    except Exception as e:
        logger.warning(f"[STARTUP] Could not pre-load OCR models: {e}")
        logger.info("[STARTUP] OCR will be loaded on first document upload")
    
    # SECURITY: Never use debug=True in production
    DEBUG_MODE = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    PORT = int(os.getenv('PORT', '1000'))
    
    if DEBUG_MODE:
        logger.warning("[STARTUP] ⚠️  Running in DEBUG mode - DO NOT use in production!")
    
    logger.info(f"[STARTUP] Starting Flask application on port {PORT}...")
    app.run(debug=DEBUG_MODE, host='0.0.0.0', port=PORT)