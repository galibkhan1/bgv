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
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, scoped_session
from flask import Flask, render_template, request, jsonify, redirect, url_for, abort, render_template_string, session
import requests
from flask_cors import CORS
from dotenv import load_dotenv
import time
from werkzeug.utils import secure_filename
import base64
from flask import send_from_directory
from werkzeug.utils import secure_filename
from aadhaar_ocr import get_ocr_reader
from aadhaar_ocr import validate_and_extract_aadhaar
from document_ocr import validate_and_extract_salary_slip, validate_and_extract_offer_letter, validate_and_extract_qualification_certificate
from smtp import send_email, send_completion_email_to_user, send_completion_email_to_company
from models import Base, User, PANVerification, AadhaarVerification, BankVerification, DocumentVerification, VerificationLog
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-change-this-in-production')
CORS(app)  

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database Configuration - Use SQLite for local development, PostgreSQL for production
DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///verification_db.sqlite')

# Create SQLAlchemy engine and session
try:
    # SQLite specific configuration
    if DATABASE_URL.startswith('sqlite'):
        engine = create_engine(DATABASE_URL, echo=False, connect_args={'check_same_thread': False})
    else:
        engine = create_engine(DATABASE_URL, echo=False)
    
    db_session = scoped_session(sessionmaker(bind=engine))
    Base.query = db_session.query_property()
    logger.info(f"[DB] Database connection established (Using: {'SQLite' if DATABASE_URL.startswith('sqlite') else 'PostgreSQL'})")
except Exception as e:
    logger.error(f"[DB] Failed to connect to database: {e}")
    engine = None
    db_session = None

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
def generate_otp_route():
    data = request.json or {}
    email = data.get('email', '').strip().lower()
    
    if not email:
        return jsonify({'success': False, 'error': 'Email is required'}), 400
    
    
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


@app.route('/logout')
def logout():
    username = session.get('user', 'Unknown')
    session.clear()
    logger.info(f"[LOGOUT] User {username} logged out")
    return redirect(url_for('login'))


@app.route('/survey')
@login_required
def survey_page():
    """Display survey form with pre-populated data"""
    user_email = session.get('user', 'unknown')
    
    # Fetch existing verification data
    pan_verification = db_session.query(PANVerification).filter_by(user_email=user_email).first()
    aadhaar_verification = db_session.query(AadhaarVerification).filter_by(user_email=user_email).first()
    bank_verification = db_session.query(BankVerification).filter_by(user_email=user_email).first()
    doc_verification = db_session.query(DocumentVerification).filter_by(user_email=user_email).first()
    
    # Prepare pre-filled data
    prefilled_data = {
        'email': user_email,
        'pan_number': pan_verification.pan_number if pan_verification else '',
        'full_name': pan_verification.full_name if pan_verification else '',
        'dob': aadhaar_verification.date_of_birth if aadhaar_verification else '',
        'father_name': '',  # Extract from Aadhaar address if available
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
    
    logger.info(f"[SURVEY] Serving survey page for {user_email} with pre-filled data")
    return render_template('survey.html', data=prefilled_data)


@app.route('/submit-survey', methods=['POST'])
@login_required
def submit_survey():
    """Handle survey form submission and save to session"""
    try:
        user_email = session.get('user', 'unknown')
        data = request.form.to_dict()
        
        # Store survey data in session temporarily
        session['survey_data'] = data
        
        logger.info(f"[SURVEY] Basic survey data saved for {user_email}")
        
        return jsonify({
            'success': True,
            'message': 'Survey data saved successfully',
            'redirect': '/survey-additional'
        })
        
    except Exception as e:
        logger.error(f"[SURVEY] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/survey-additional')
@login_required
def survey_additional():
    """Render additional details page"""
    user_email = session.get('user', 'unknown')
    
    # Check if basic survey was completed
    if not session.get('survey_data'):
        logger.warning(f"[SURVEY] User {user_email} tried to access additional details without completing basic survey")
        return redirect(url_for('survey_page'))
    
    logger.info(f"[SURVEY] Serving additional details page for {user_email}")
    return render_template('survey_additional.html')


@app.route('/submit-additional-details', methods=['POST'])
@login_required
def submit_additional_details():
    """Handle additional details form submission with file upload"""
    try:
        user_email = session.get('user', 'unknown')
        
        # Get basic survey data from session
        survey_data = session.get('survey_data', {})
        
        if not survey_data:
            return jsonify({'success': False, 'error': 'Basic survey data not found'}), 400
        
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
                
                # Try S3 upload
                s3_key = f"{safe_email}/documents/passport_photo_{timestamp}.{file_ext}"
                
                if s3_client and S3_BUCKET_NAME:
                    try:
                        s3_client.put_object(
                            Bucket=S3_BUCKET_NAME,
                            Key=s3_key,
                            Body=file.read(),
                            ContentType=f'image/{file_ext}',
                            Metadata={'user_email': user_email, 'document_type': 'passport_photo'}
                        )
                        passport_photo_url = f"https://{S3_BUCKET_NAME}.s3.amazonaws.com/{s3_key}"
                        logger.info(f"[S3] Passport photo uploaded: {s3_key}")
                    except Exception as e:
                        logger.warning(f"[S3] Failed to upload passport photo: {e}")
                
                # Fallback to local storage
                if not passport_photo_url:
                    upload_dir = os.path.join(os.getcwd(), 'uploads', safe_email, 'documents')
                    os.makedirs(upload_dir, exist_ok=True)
                    local_filename = f"passport_photo_{timestamp}.{file_ext}"
                    filepath = os.path.join(upload_dir, local_filename)
                    file.seek(0)
                    file.save(filepath)
                    passport_photo_url = f"/uploads/{safe_email}/documents/{local_filename}"
                    logger.info(f"[LOCAL] Passport photo saved: {filepath}")
        
        # Combine all data
        complete_data = {**survey_data, **additional_data, 'passport_photo_url': passport_photo_url}
        
        # Here you would save to database
        # For now, just log it
        logger.info(f"[SURVEY] Complete survey submitted by {user_email}")
        logger.info(f"[SURVEY] Data: {complete_data}")
        
        # Clear session data
        session.pop('survey_data', None)
        
        return jsonify({
            'success': True,
            'message': 'All details submitted successfully'
        })
        
    except Exception as e:
        logger.error(f"[SURVEY] Error submitting additional details: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/uploads/<path:filepath>')
@login_required
def serve_uploaded_file(filepath):
    """Serve locally stored uploaded files"""
    
    uploads_dir = os.path.join(os.getcwd(), 'uploads')
    return send_from_directory(uploads_dir, filepath)


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


@app.route('/bank-verification')
@login_required
def bank_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    logger.info("[BANK VERIFICATION] Serving Bank verification page")
    return render_template('bank_verification.html')


@app.route('/document-verification')
@login_required
def document_verification() -> str:
    # Check if consent has been given
    if not session.get('consent_given', False):
        return redirect(url_for('consent'))
    
    user_email = session.get('user', 'unknown')
    
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
    logger.info(f"[BANK] Verifying Bank details IFSC: {ifsc}, Account: {account_number}")
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
        
        logger.info(f"[AADHAAR OCR] Extracted - Number: {aadhaar_number}, Name: {full_name}, DOB: {dob}, Gender: {gender}")
        
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
    
    logger.info("[STARTUP] Starting Flask application...")
    app.run(debug=True, port=1000)