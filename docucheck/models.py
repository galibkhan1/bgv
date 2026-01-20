"""
Database Models for BGV Setu Application
"""
from datetime import datetime
from sqlalchemy import Column, Integer, String, DateTime, Text, Boolean, JSON
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()

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
    status = Column(String(50)) 
    verification_data = Column(JSON)
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
    verification_method = Column(String(50)) 
    digilocker_request_id = Column(String(255))
    s3_file_key = Column(String(500))
    s3_file_url = Column(Text)
    verification_data = Column(JSON) 
    verified_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class BankVerification(Base):
    __tablename__ = 'bank_verifications'
    
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    account_number = Column(String(50), nullable=False)
    ifsc_code = Column(String(11), nullable=False)
    account_holder_name = Column(String(255))
    bank_name = Column(String(255))
    branch_name = Column(String(255))
    status = Column(String(50)) 
    verification_data = Column(JSON)  
    verified_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)

class DocumentVerification(Base):
    __tablename__ = 'document_verifications'
    
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    qualification_certificate_s3_key = Column(String(500))
    qualification_certificate_s3_url = Column(Text)
    qualification_certificate_filename = Column(String(255))

    qualification_certificate_ocr_data = Column(JSON)

    offer_letter_s3_key = Column(String(500))
    offer_letter_s3_url = Column(Text)
    offer_letter_filename = Column(String(255))
 
    offer_letter_ocr_data = Column(JSON)
    salary_slip_1_s3_key = Column(String(500))
    salary_slip_1_s3_url = Column(Text)
    salary_slip_1_filename = Column(String(255))
    salary_slip_1_ocr_data = Column(JSON)
    salary_slip_2_s3_key = Column(String(500))
    salary_slip_2_s3_url = Column(Text)
    salary_slip_2_filename = Column(String(255))
    salary_slip_2_ocr_data = Column(JSON)
    salary_slip_3_s3_key = Column(String(500))
    salary_slip_3_s3_url = Column(Text)
    salary_slip_3_filename = Column(String(255))
    salary_slip_3_ocr_data = Column(JSON)
    status = Column(String(50))
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class VerificationLog(Base):
    __tablename__ = 'verification_logs'
    
    id = Column(Integer, primary_key=True)
    user_email = Column(String(255), nullable=False)
    verification_status = Column(String(50))  # completed, partial, failed
    pan_verified = Column(Boolean, default=False)
    aadhaar_verified = Column(Boolean, default=False)
    documents_verified = Column(Boolean, default=False)
    bank_verified = Column(Boolean, default=False)
    verification_completed_at = Column(DateTime, default=datetime.utcnow)
    emails_sent = Column(Boolean, default=False)
    user_email_sent = Column(Boolean, default=False)
    company_email_sent = Column(Boolean, default=False)
    notes = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)


