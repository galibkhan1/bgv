import os
import re
import logging
from typing import Optional, Dict, Any
from functools import wraps
import random
from datetime import datetime, timedelta
import xml.etree.ElementTree as ET
import boto3
from botocore.exceptions import ClientError
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, scoped_session

from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, render_template_string, session
import requests
from flask_cors import CORS
from dotenv import load_dotenv
import time

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')
CORS(app)  

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# PostgreSQL Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL', 'postgresql://postgres:password@localhost:5432/verification_db')

# Create SQLAlchemy engine and session
try:
    engine = create_engine(DATABASE_URL, echo=False)
    db_session = scoped_session(sessionmaker(bind=engine))
    Base = declarative_base()
    Base.query = db_session.query_property()
    logger.info("[DB] Database connection established")
except Exception as e:
    logger.error(f"[DB] Failed to connect to database: {e}")
    engine = None
    db_session = None
    Base = declarative_base()

# Database Models
class User(Base):
    __tablename__ = 'users'
    
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, nullable=False)
    name = Column(String(255))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class PANVerification(Base):
    __tablename__ = 'pan_verifications'
    
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    pan_number = Column(String(10), nullable=False)
    full_name = Column(String(255))
    status = Column(String(50))  # valid, invalid
    verification_data = Column(JSON)  # Store full API response
    verified_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class AadhaarVerification(Base):
    __tablename__ = 'aadhaar_verifications'
    
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    aadhaar_number = Column(String(20))
    masked_number = Column(String(20))
    full_name = Column(String(255))
    date_of_birth = Column(String(50))
    gender = Column(String(10))
    address = Column(Text)
    verification_method = Column(String(50))  # digilocker, manual_upload
    digilocker_request_id = Column(String(255))
    s3_file_key = Column(String(500))
    s3_file_url = Column(Text)
    verification_data = Column(JSON)  # Store full API response
    verified_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

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

# Email configuration
BREVO_API_KEY = os.getenv('BREVO_API_KEY')
SENDER_EMAIL = os.getenv('SENDER_EMAIL', 'noreply@example.com')
SENDER_NAME = os.getenv('SENDER_NAME', 'Verification Portal')

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
        abort(500, description="External API request failed")


def generate_otp():
    """Generate a 6-digit OTP"""
    return str(random.randint(100000, 999999))


def send_otp_email(email: str, otp: str):
    """
    Send OTP via email using Brevo REST API
    Fallback to console logging if API key not configured
    """
    try:
        if BREVO_API_KEY and BREVO_API_KEY != 'your-brevo-api-key-here':
            # Send via Brevo REST API
            url = "https://api.brevo.com/v3/smtp/email"
            headers = {
                "accept": "application/json",
                "api-key": "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",
                "content-type": "application/json"
            }
            payload = {
                "sender": {
                    "name": "BGV",
                    "email": "extra0848@gmail.com"
                },
                "to": [{"email": email}],
                "subject": "Your Verification Code",
                "htmlContent": f"""
                    <html>
                        <body style="font-family: Arial, sans-serif; padding: 20px;">
                            <p>Hi,</p>
                            <p>This is your verification code <strong>{otp}</strong>.</p>
                            <p>Thanks</p>
                        </body>
                    </html>
                """
            }
            
            response = requests.post(url, json=payload, headers=headers, timeout=10)
            
            if response.status_code == 201:
                logger.info(f"[OTP] Email sent successfully to {email}")
                return True
            else:
                logger.error(f"[OTP] Failed to send email: {response.status_code} - {response.text}")
                # Fallback to console
                print(f"\n{'='*50}")
                print(f"Hi,")
                print(f"")
                print(f"This is your verification code {otp}.")
                print(f"")
                print(f"Thanks")
                print(f"{'='*50}\n")
                return True
            
        else:
            # No API key configured - log to console
            logger.info(f"[OTP] No email service configured. Logging OTP to console.")
            print(f"\n{'='*50}")
            print(f"Hi,")
            print(f"")
            print(f"This is your verification code {otp}.")
            print(f"")
            print(f"Thanks")
            print(f"{'='*50}\n")
            return True
            
    except requests.exceptions.RequestException as e:
        logger.error(f"[OTP] Request error sending email: {e}")
        # Fallback to console
        print(f"\n{'='*50}")
        print(f"Hi,")
        print(f"")
        print(f"This is your verification code {otp}.")
        print(f"")
        print(f"Thanks")
        print(f"{'='*50}\n")
        return True
    except Exception as e:
        logger.error(f"[OTP] Error sending email: {e}")
        # Fallback to console
        print(f"\n{'='*50}")
        print(f"Hi,")
        print(f"")
        print(f"This is your verification code {otp}.")
        print(f"")
        print(f"Thanks")
        print(f"{'='*50}\n")
        return True


@app.route('/generate-otp', methods=['POST'])
def generate_otp_route():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    # Validate email format
    email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    if not re.match(email_regex, email):
        return jsonify({'success': False, 'error': 'Invalid email format'}), 400
    
    # Allow ANY valid email - no restrictions
    # In production, you might want to add rate limiting
    
    # Generate OTP
    otp = generate_otp()
    expiry = datetime.now() + timedelta(minutes=5)  # OTP valid for 5 minutes
    
    # Store OTP with expiry
    otp_storage[email] = {
        'otp': otp,
        'expiry': expiry,
        'attempts': 0
    }
    
    # Send OTP via email (demo implementation)
    email_sent = send_otp_email(email, otp)
    
    logger.info(f"[OTP] OTP generated for {email}")
    
    message = 'OTP sent to your email. Valid for 5 minutes.'
    if not BREVO_API_KEY or BREVO_API_KEY == 'your-brevo-api-key-here':
        message = 'OTP generated! Check the console/terminal for your OTP (Email service not configured).'
    
    return jsonify({
        'success': True,
        'message': message
    })


@app.route('/verify-otp', methods=['POST'])
def verify_otp_route():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    otp = data.get('otp', '').strip()
    
    if not email or not otp:
        return jsonify({'success': False, 'error': 'Email and OTP are required'}), 400
    
    # Check if OTP exists for this email
    if email not in otp_storage:
        return jsonify({'success': False, 'error': 'No OTP generated for this email'}), 400
    
    stored_data = otp_storage[email]
    
    # Check if OTP is expired
    if datetime.now() > stored_data['expiry']:
        del otp_storage[email]
        return jsonify({'success': False, 'error': 'OTP has expired. Please generate a new one'}), 400
    
    # Check attempts (max 3 attempts)
    if stored_data['attempts'] >= 3:
        del otp_storage[email]
        return jsonify({'success': False, 'error': 'Maximum attempts exceeded. Please generate a new OTP'}), 400
    
    # Verify OTP
    if stored_data['otp'] == otp:
        # OTP is correct - create session (but mark as not consented yet)
        session['user'] = email
        session['user_name'] = email.split('@')[0].capitalize()
        session['consent_given'] = False
        del otp_storage[email]  # Remove used OTP
        logger.info(f"[LOGIN] User {email} logged in successfully via OTP")
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
    # If user is already logged in, check if consent given
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


@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    session.clear()
    logger.info(f"[LOGOUT] User {username} logged out")
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    logger.info("[INDEX] Redirecting to PAN verification page")
    return redirect(url_for('pan_verification'))


@app.route('/pan-verification')
@login_required
def pan_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    logger.info("[PAN VERIFICATION] Serving PAN verification page")
    return render_template('pan_verification.html')


@app.route('/aadhaar-verification')
@login_required
def aadhaar_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    logger.info("[AADHAAR VERIFICATION] Serving Aadhaar verification page")
    return render_template('aadhaar_verification.html')


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
    logger.info(f"[BANK] Verifying Bank details IFSC: {ifsc}, Account: {account_number}")
    result = call_setu_api(BANK_API_URL, payload, BANK_HEADERS)
    return jsonify(result)


@app.route('/digilocker/create-request', methods=['GET', 'POST'])
@login_required
def create_digilocker_request():
    payload = {
        "redirectUrl": REDIRECT_URL,
        "consent": "Y",
        "types": ["PAN_CARD", "AADHAAR", "DL"] 
    }

    logger.info(f"[DL] Creating DigiLocker request: {payload}")
    
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

        logger.info(f"[DL] Redirecting user to DigiLocker: {login_url}")
        return redirect(login_url)

    except Exception as e:
        logger.error(f"[DL] Error creating request: {e}")
        abort(500, "Failed to create DigiLocker request")



@app.route('/digilocker/callback')
@login_required
def digilocker_callback():
    request_id = request.args.get("id")
    success = request.args.get("success")
    
    success_bool = success and success.lower() == "true"

    logger.info(f"[DL CALLBACK] request_id={request_id}, success={success}")

    if not request_id:
        abort(400, "Missing request ID")

    if not success_bool:
        msg = request.args.get("errMessage", "User denied permission")
        logger.error(f"[DL CALLBACK] User failed login: {msg}")
        session['digilocker_error'] = msg
        return redirect(url_for('aadhaar_verification'))

    # Store the request ID in session for later retrieval
    session['digilocker_request_id'] = request_id
    session['digilocker_success'] = True
    
    logger.info(f"[DL CALLBACK] Login successful, redirecting to Aadhaar verification page")
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
                
                # Try different paths where XML might be
                if isinstance(aadhaar_raw, dict):
                    xml_string = (
                        aadhaar_raw.get('xml') or 
                        aadhaar_raw.get('data') or
                        aadhaar_raw.get('aadhaarXml') or
                        aadhaar_raw.get('content')
                    )
                
                logger.info(f"[DL] XML string found: {bool(xml_string)}")
                
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

       
        consented_documents = status_data.get("scope", [])
        logger.info(f"[DL] User consented scope: {consented_documents}")

        if consented_documents:
            catalog_url = f"{DIGILOCKER_BASE_URL}/documents"
            catalog_res = requests.get(catalog_url, headers=DIGILOCKER_HEADERS, timeout=10)
            catalog_res.raise_for_status()

            catalog_list = catalog_res.json().get("documents", [])
            logger.info(f"[DL] Catalog loaded: {len(catalog_list)} documents")

            user_doc_defs = []
            for d in catalog_list:
                doc_type = (
                    d.get("docType") or
                    d.get("documentType") or
                    d.get("documentIdentifier")
                )
                if doc_type in consented_documents:
                    d["docType"] = doc_type
                    user_doc_defs.append(d)

            fetched_docs = []

            for doc_def in user_doc_defs:
                payload = {
                    "docType": doc_def["docType"],
                    "orgId": doc_def.get("orgId"),
                    "format": "pdf",
                    "consent": "Y",
                    "parameters": doc_def.get("parameters", {})
                }

                fetch_url = f"{DIGILOCKER_BASE_URL}/{request_id}/document"
                logger.info(f"[DL] Fetching document: {payload}")

                fetch_res = requests.post(
                    fetch_url, json=payload, headers=DIGILOCKER_HEADERS, timeout=20
                )

                if fetch_res.status_code == 200:
                    fetched_docs.append(fetch_res.json())
                else:
                    logger.warning(f"[DL] Document fetch failed: {fetch_res.text}")

            normalized["documents"] = fetched_docs

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
    """Handle manual Aadhaar card upload and save to S3"""
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
        
        # Get user email
        user_email = session.get('user', 'unknown')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate S3 key with email and document type
        from werkzeug.utils import secure_filename
        safe_email = secure_filename(user_email.replace('@', '_at_').replace('.', '_'))
        s3_key = f"{safe_email}/documents/aadhaar_{timestamp}.{file_ext}"
        
        file_url = None
        
        # Try to upload to S3
        if s3_client and S3_BUCKET_NAME:
            try:
                # Read file content
                file.seek(0)
                file_content = file.read()
                
                # Determine content type
                content_type_map = {
                    'jpg': 'image/jpeg',
                    'jpeg': 'image/jpeg',
                    'png': 'image/png',
                    'pdf': 'application/pdf'
                }
                content_type = content_type_map.get(file_ext, 'application/octet-stream')
                
                # Upload to S3
                s3_client.put_object(
                    Bucket=S3_BUCKET_NAME,
                    Key=s3_key,
                    Body=file_content,
                    ContentType=content_type,
                    Metadata={
                        'user_email': user_email,
                        'document_type': 'aadhaar',
                        'upload_time': timestamp
                    }
                )
                
                # Generate S3 URL
                file_url = f"https://{S3_BUCKET_NAME}.s3.{AWS_REGION}.amazonaws.com/{s3_key}"
                
                logger.info(f"[AADHAAR UPLOAD] File uploaded to S3: {s3_key} for user: {user_email}")
                
                # Store upload info in session
                session['aadhaar_uploaded'] = True
                session['aadhaar_s3_key'] = s3_key
                session['aadhaar_s3_url'] = file_url
                session['aadhaar_upload_time'] = timestamp
                
                # Save to database
                if db_session:
                    try:
                        aadhaar_verification = AadhaarVerification(
                            user_email=user_email,
                            verification_method='manual_upload',
                            s3_file_key=s3_key,
                            s3_file_url=file_url,
                            verification_data={'upload_method': 'manual', 'file_type': file_ext}
                        )
                        db_session.add(aadhaar_verification)
                        db_session.commit()
                        logger.info(f"[DB] Manual Aadhaar upload saved for user: {user_email}")
                    except Exception as e:
                        logger.error(f"[DB] Failed to save manual Aadhaar upload: {e}")
                        db_session.rollback()
                
                return jsonify({
                    'success': True,
                    'message': 'Aadhaar uploaded successfully to S3',
                    's3_key': s3_key,
                    'url': file_url
                })
                
            except ClientError as e:
                logger.error(f"[AADHAAR UPLOAD] S3 upload failed: {e}")
                # Fall back to local storage
                pass
        
        # Fallback: Save locally if S3 is not configured or upload failed
        upload_dir = os.path.join(os.getcwd(), 'uploads', 'aadhaar')
        os.makedirs(upload_dir, exist_ok=True)
        
        filename = secure_filename(f"{safe_email}_aadhaar_{timestamp}.{file_ext}")
        filepath = os.path.join(upload_dir, filename)
        
        # Reset file pointer and save locally
        file.seek(0)
        file.save(filepath)
        
        # Store upload info in session
        session['aadhaar_uploaded'] = True
        session['aadhaar_file_path'] = filepath
        session['aadhaar_upload_time'] = timestamp
        
        # Save to database
        if db_session:
            try:
                aadhaar_verification = AadhaarVerification(
                    user_email=user_email,
                    verification_method='manual_upload',
                    s3_file_key=filename,
                    verification_data={'upload_method': 'manual_local', 'file_type': file_ext, 'file_path': filepath}
                )
                db_session.add(aadhaar_verification)
                db_session.commit()
                logger.info(f"[DB] Manual Aadhaar upload (local) saved for user: {user_email}")
            except Exception as e:
                logger.error(f"[DB] Failed to save manual Aadhaar upload (local): {e}")
                db_session.rollback()
        
        logger.info(f"[AADHAAR UPLOAD] File saved locally: {filepath} for user: {user_email}")
        
        return jsonify({
            'success': True,
            'message': 'Aadhaar uploaded successfully (local storage)',
            'filename': filename
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
    app.run(debug=True, port=1000)