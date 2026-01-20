
import re
import cv2
import numpy as np
from PIL import Image
import easyocr
import io
from typing import Dict, Optional, Tuple
import logging
from aadhaar_ocr import get_ocr_reader

logger = logging.getLogger(__name__)



class SalarySlipOCR:
    """Extract and validate salary slip information from images"""
    
    # Common salary slip keywords
    SALARY_KEYWORDS = ['salary', 'pay slip', 'payslip', 'payment', 'earnings', 'deductions', 'net pay', 'gross pay', 'basic pay', 'ctc']
    
    # Pattern to extract amounts (salary values)
    AMOUNT_PATTERN = r'₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)'
    
    # Pattern to extract UAN number (12 digits)
    UAN_PATTERN = r'\b(\d{12})\b'
    
    # Pattern to extract dates
    DATE_PATTERNS = [
        r'\b(?:month|period|date)\s*:?\s*([A-Za-z]+[\s-]\d{4})',  # e.g., "Month: January 2024"
        r'\b([A-Za-z]+[\s-]\d{4})\b',  # e.g., "January 2024"
        r'\b(\d{1,2}[/-]\d{1,2}[/-]\d{4})\b',  # e.g., "01/01/2024"
    ]
    
    @staticmethod
    def extract_text_from_image(image: Image.Image) -> str:
        """
        Extract text from image using EasyOCR
        """
        try:
            logger.info("[SALARY OCR] Converting image to array...")
            img_array = np.array(image.convert('RGB'))
            
            logger.info("[SALARY OCR] Getting OCR reader...")
            reader = get_ocr_reader()
            
            logger.info("[SALARY OCR] Reading text from salary slip...")
            results = reader.readtext(img_array, detail=0)
            
            text = '\n'.join(results)
            
            logger.info(f"[SALARY OCR] Extracted {len(text)} characters from salary slip")
            return text
        except Exception as e:
            logger.error(f"[SALARY OCR] Error: {str(e)}")
            raise
    
    @staticmethod
    def is_salary_slip(text: str) -> bool:
        """
        Verify if the document is a salary slip
        """
        text_lower = text.lower()
        
        keyword_count = sum(1 for keyword in SalarySlipOCR.SALARY_KEYWORDS 
                           if keyword in text_lower)
        
        # Check for common salary-related terms
        return keyword_count >= 2
    
    @staticmethod
    def extract_employee_name(text: str) -> Optional[str]:
        """
        Extract employee name from salary slip
        """
        lines = text.strip().split('\n')
        
        for i, line in enumerate(lines[:15]):
            line = line.strip()
            
            # Look for "Employee Name:", "Name:", etc.
            name_patterns = [
                r'(?:employee\s+name|emp\s+name|name)\s*:?\s*([A-Z][A-Za-z\s]{2,50})',
                r'^([A-Z][A-Za-z\s]{5,50})$'  # Full name pattern
            ]
            
            for pattern in name_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    name = match.group(1).strip()
                    # Filter out company names and common headers
                    skip_keywords = ['pvt', 'ltd', 'limited', 'company', 'corporation', 'salary', 'payslip']
                    if not any(keyword in name.lower() for keyword in skip_keywords):
                        return name
        
        return None
    
    @staticmethod
    def extract_company_name(text: str) -> Optional[str]:
        """
        Extract company name from salary slip
        """
        lines = text.strip().split('\n')
        
        for i, line in enumerate(lines[:10]):
            line = line.strip()
            
            # Company name usually at the top, may contain Pvt Ltd, Limited, etc.
            company_keywords = ['pvt', 'ltd', 'limited', 'company', 'corporation', 'inc']
            if any(keyword in line.lower() for keyword in company_keywords):
                # Clean the line
                if len(line) > 3 and len(line) < 100:
                    return line
        
        return None
    
    @staticmethod
    def extract_month_year(text: str) -> Optional[str]:
        """
        Extract month and year from salary slip
        """
        for pattern in SalarySlipOCR.DATE_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_uan_number(text: str) -> Optional[str]:

        uan_patterns = [
            r'(?:uan|uan\s+no|uan\s+number|universal\s+account\s+number)\s*:?\s*(\d{12})',
            r'\buan\s*:?\s*(\d{12})\b'
        ]
        
        for pattern in uan_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        lines = text.strip().split('\n')
        for line in lines:
            if 'uan' in line.lower():
            
                match = re.search(SalarySlipOCR.UAN_PATTERN, line)
                if match:
                    return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_net_pay(text: str) -> Optional[str]:
        """
        Extract net pay amount from salary slip
        """
        text_lower = text.lower()
        
        # Look for net pay, net salary, take home
        net_pay_patterns = [
            r'(?:net\s+pay|net\s+salary|take\s+home)\s*:?\s*₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)',
            r'(?:total\s+net\s+pay)\s*:?\s*₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)'
        ]
        
        for pattern in net_pay_patterns:
            match = re.search(pattern, text_lower)
            if match:
                return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_gross_pay(text: str) -> Optional[str]:
        """
        Extract gross pay amount from salary slip
        """
        text_lower = text.lower()
        
        # Look for gross pay, gross salary
        gross_pay_patterns = [
            r'(?:gross\s+pay|gross\s+salary)\s*:?\s*₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)',
            r'(?:total\s+gross\s+pay)\s*:?\s*₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)'
        ]
        
        for pattern in gross_pay_patterns:
            match = re.search(pattern, text_lower)
            if match:
                return match.group(1).strip()
        
        return None
    
    @staticmethod
    def process_salary_slip(file_bytes: bytes, filename: str) -> Dict[str, any]:
        
        result = {
            'is_valid': False,
            'is_salary_slip': False,
            'employee_name': None,
            'company_name': None,
            'month_year': None,
            'net_pay': None,
            'gross_pay': None,
            'uan_number': None,
            'raw_text': '',
            'error': None
        }
        
        try:
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext in ['jpg', 'jpeg', 'png', 'pdf']:
                image = Image.open(io.BytesIO(file_bytes))
                text = SalarySlipOCR.extract_text_from_image(image)
            else:
                result['error'] = "Unsupported file format"
                return result
            
            result['raw_text'] = text
            
            result['is_salary_slip'] = SalarySlipOCR.is_salary_slip(text)
            
            if not result['is_salary_slip']:
                result['error'] = "Document does not appear to be a salary slip"
                return result
            
            result['employee_name'] = SalarySlipOCR.extract_employee_name(text)
            result['company_name'] = SalarySlipOCR.extract_company_name(text)
            result['month_year'] = SalarySlipOCR.extract_month_year(text)
            result['net_pay'] = SalarySlipOCR.extract_net_pay(text)
            result['gross_pay'] = SalarySlipOCR.extract_gross_pay(text)
            result['uan_number'] = SalarySlipOCR.extract_uan_number(text)
            
            result['is_valid'] = result['is_salary_slip']
            
            return result
            
        except Exception as e:
            result['error'] = f"Processing error: {str(e)}"
            logger.error(f"[SALARY OCR] Error processing: {e}")
            return result


class OfferLetterOCR:
    """Extract and validate offer letter information from images"""
    
    # Common offer letter keywords
    OFFER_KEYWORDS = ['offer letter', 'letter of offer', 'appointment letter', 'employment offer', 'joining', 'position', 'designation']
    
    @staticmethod
    def extract_text_from_image(image: Image.Image) -> str:
        """
        Extract text from image using EasyOCR
        """
        try:
            logger.info("[OFFER OCR] Converting image to array...")
            img_array = np.array(image.convert('RGB'))
            
            logger.info("[OFFER OCR] Getting OCR reader...")
            reader = get_ocr_reader()
            
            logger.info("[OFFER OCR] Reading text from offer letter...")
            results = reader.readtext(img_array, detail=0)
            
            text = '\n'.join(results)
            
            logger.info(f"[OFFER OCR] Extracted {len(text)} characters from offer letter")
            return text
        except Exception as e:
            logger.error(f"[OFFER OCR] Error: {str(e)}")
            raise
    
    @staticmethod
    def is_offer_letter(text: str) -> bool:
        """
        Verify if the document is an offer letter
        """
        text_lower = text.lower()
        
        keyword_count = sum(1 for keyword in OfferLetterOCR.OFFER_KEYWORDS 
                           if keyword in text_lower)
        
        return keyword_count >= 1
    
    @staticmethod
    def extract_candidate_name(text: str) -> Optional[str]:
        """
        Extract candidate name from offer letter
        """
        lines = text.strip().split('\n')
        
        for i, line in enumerate(lines[:20]):
            line = line.strip()
            
            # Look for "Dear", "Mr.", "Ms.", "Miss" patterns
            name_patterns = [
                r'(?:dear|mr\.|ms\.|miss)\s+([A-Z][A-Za-z\s]{2,50})',
                r'(?:candidate\s+name|name)\s*:?\s*([A-Z][A-Za-z\s]{2,50})'
            ]
            
            for pattern in name_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    name = match.group(1).strip()
                    # Remove trailing commas
                    name = name.rstrip(',')
                    return name
        
        return None
    
    @staticmethod
    def extract_designation(text: str) -> Optional[str]:
        """
        Extract job designation from offer letter
        """
        text_lower = text.lower()
        
        # Look for position, designation, role
        designation_patterns = [
            r'(?:position|designation|role|title)\s*:?\s*([A-Za-z\s]{3,50})',
            r'(?:as\s+a|as\s+an)\s+([A-Z][A-Za-z\s]{3,50})'
        ]
        
        for pattern in designation_patterns:
            match = re.search(pattern, text_lower)
            if match:
                designation = match.group(1).strip()
                # Clean up
                designation = designation.split('\n')[0].strip()
                if len(designation) > 3 and len(designation) < 50:
                    return designation.title()
        
        return None
    
    @staticmethod
    def extract_company_name(text: str) -> Optional[str]:
        """
        Extract company name from offer letter
        """
        lines = text.strip().split('\n')
        
        for i, line in enumerate(lines[:10]):
            line = line.strip()
            
            # Company name usually at the top
            company_keywords = ['pvt', 'ltd', 'limited', 'company', 'corporation', 'inc']
            if any(keyword in line.lower() for keyword in company_keywords):
                if len(line) > 3 and len(line) < 100:
                    return line
        
        return None
    
    @staticmethod
    def extract_joining_date(text: str) -> Optional[str]:
        """
        Extract joining date from offer letter
        """
        joining_patterns = [
            r'(?:joining\s+date|date\s+of\s+joining|start\s+date)\s*:?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4})',
            r'(?:joining\s+on|join\s+on|start\s+on)\s*:?\s*(\d{1,2}[/-]\d{1,2}[/-]\d{4})',
            r'(?:joining\s+date|date\s+of\s+joining)\s*:?\s*([A-Za-z]+\s+\d{1,2},?\s+\d{4})'
        ]
        
        for pattern in joining_patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_ctc(text: str) -> Optional[str]:
        """
        Extract CTC (Cost to Company) from offer letter
        """
        text_lower = text.lower()
        
        # Look for CTC, annual salary, compensation
        ctc_patterns = [
            r'(?:ctc|cost\s+to\s+company|annual\s+salary|compensation)\s*:?\s*₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)',
            r'(?:package|salary)\s+of\s+₹?\s*(\d{1,3}(?:,\d{3})*(?:\.\d{2})?)'
        ]
        
        for pattern in ctc_patterns:
            match = re.search(pattern, text_lower)
            if match:
                return match.group(1).strip()
        
        return None
    
    @staticmethod
    def process_offer_letter(file_bytes: bytes, filename: str) -> Dict[str, any]:
        """
        Main function to process offer letter and extract information
        
        Returns:
        {
            'is_valid': bool,
            'is_offer_letter': bool,
            'candidate_name': str or None,
            'company_name': str or None,
            'designation': str or None,
            'joining_date': str or None,
            'ctc': str or None,
            'raw_text': str,
            'error': str or None
        }
        """
        result = {
            'is_valid': False,
            'is_offer_letter': False,
            'candidate_name': None,
            'company_name': None,
            'designation': None,
            'joining_date': None,
            'ctc': None,
            'raw_text': '',
            'error': None
        }
        
        try:
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext in ['jpg', 'jpeg', 'png', 'pdf']:
                image = Image.open(io.BytesIO(file_bytes))
                text = OfferLetterOCR.extract_text_from_image(image)
            else:
                result['error'] = "Unsupported file format"
                return result
            
            result['raw_text'] = text
            
            result['is_offer_letter'] = OfferLetterOCR.is_offer_letter(text)
            
            if not result['is_offer_letter']:
                result['error'] = "Document does not appear to be an offer letter"
                return result
            
            result['candidate_name'] = OfferLetterOCR.extract_candidate_name(text)
            result['company_name'] = OfferLetterOCR.extract_company_name(text)
            result['designation'] = OfferLetterOCR.extract_designation(text)
            result['joining_date'] = OfferLetterOCR.extract_joining_date(text)
            result['ctc'] = OfferLetterOCR.extract_ctc(text)
            
            result['is_valid'] = result['is_offer_letter']
            
            return result
            
        except Exception as e:
            result['error'] = f"Processing error: {str(e)}"
            logger.error(f"[OFFER OCR] Error processing: {e}")
            return result


def validate_and_extract_salary_slip(file_bytes: bytes, filename: str) -> Tuple[bool, Dict]:
    """
    Convenience function to validate and extract salary slip information
    
    Returns:
        (success: bool, data: dict)
    """
    result = SalarySlipOCR.process_salary_slip(file_bytes, filename)
    
    if result['error']:
        return False, {'error': result['error'], 'raw_text': result.get('raw_text', '')}
    
    if not result['is_salary_slip']:
        return False, {'error': 'Uploaded document is not a salary slip', 'raw_text': result.get('raw_text', '')}
    
    return result['is_valid'], result


def validate_and_extract_offer_letter(file_bytes: bytes, filename: str) -> Tuple[bool, Dict]:
    """
    Convenience function to validate and extract offer letter information
    
    Returns:
        (success: bool, data: dict)
    """
    result = OfferLetterOCR.process_offer_letter(file_bytes, filename)
    
    if result['error']:
        return False, {'error': result['error'], 'raw_text': result.get('raw_text', '')}
    
    if not result['is_offer_letter']:
        return False, {'error': 'Uploaded document is not an offer letter', 'raw_text': result.get('raw_text', '')}
    
    return result['is_valid'], result


class QualificationCertificateOCR:
    """Extract and validate qualification certificate information from images"""
    
    # Common qualification certificate keywords
    QUALIFICATION_KEYWORDS = ['certificate', 'degree', 'diploma', 'bachelor', 'master', 'university', 
                             'college', 'institute', 'education', 'graduation', 'marks', 'grade', 'cgpa',
                             'awarded', 'conferred', 'passed', 'examination']
    
    # Qualification types
    QUALIFICATION_TYPES = ['bachelor', 'master', 'phd', 'doctorate', 'diploma', 'degree', 'b.tech', 
                          'b.e', 'm.tech', 'm.e', 'mba', 'mca', 'bca', 'b.sc', 'm.sc', 'b.com', 'm.com',
                          'b.a', 'm.a', 'bba', 'graduation', 'post graduation']
    
    # Date patterns
    DATE_PATTERNS = [
        r'\b(\d{1,2}[-/]\d{1,2}[-/]\d{4})\b',  # DD/MM/YYYY or DD-MM-YYYY
        r'\b(\d{4})\b',  # Year only
        r'\b([A-Za-z]+\s+\d{4})\b',  # Month Year
    ]
    
    @staticmethod
    def extract_text_from_image(image: Image.Image) -> str:
        """Extract text from image using EasyOCR"""
        try:
            logger.info("[QUALIFICATION OCR] Converting image to array...")
            img_array = np.array(image.convert('RGB'))
            
            logger.info("[QUALIFICATION OCR] Getting OCR reader...")
            reader = get_ocr_reader()
            
            logger.info("[QUALIFICATION OCR] Reading text from certificate...")
            results = reader.readtext(img_array, detail=0)
            
            text = '\n'.join(results)
            
            logger.info(f"[QUALIFICATION OCR] Extracted {len(text)} characters from certificate")
            return text
        except Exception as e:
            logger.error(f"[QUALIFICATION OCR] Error: {str(e)}")
            raise
    
    @staticmethod
    def is_qualification_certificate(text: str) -> bool:
        """Verify if the document is a qualification certificate"""
        text_lower = text.lower()
        
        keyword_count = sum(1 for keyword in QualificationCertificateOCR.QUALIFICATION_KEYWORDS 
                           if keyword in text_lower)
        
        return keyword_count >= 3
    
    @staticmethod
    def extract_student_name(text: str) -> Optional[str]:
        """Extract student/candidate name from certificate"""
        lines = text.strip().split('\n')
        
        for line in lines[:20]:
            line = line.strip()
            
            name_patterns = [
                r'(?:name|student|candidate)\s*:?\s*([A-Z][A-Za-z\s]{2,50})',
                r'(?:this is to certify that)\s+([A-Z][A-Za-z\s]{5,50})',
                r'(?:awarded to|conferred upon|granted to)\s+([A-Z][A-Za-z\s]{5,50})',
            ]
            
            for pattern in name_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    name = match.group(1).strip()
                    skip_keywords = ['university', 'college', 'institute', 'school', 'certificate', 'degree']
                    if not any(keyword in name.lower() for keyword in skip_keywords):
                        return name
        
        return None
    
    @staticmethod
    def extract_institution_name(text: str) -> Optional[str]:
        """Extract university/college/institution name"""
        lines = text.strip().split('\n')
        
        for line in lines[:15]:
            line = line.strip()
            
            institution_patterns = [
                r'(.*?(?:university|college|institute|institution).*?)(?:\n|$)',
                r'(?:from|of)\s+(.*?(?:university|college|institute).*?)(?:\n|$)',
            ]
            
            for pattern in institution_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_qualification_type(text: str) -> Optional[str]:
        """Extract type of qualification (Bachelor's, Master's, etc.)"""
        text_lower = text.lower()
        
        for qual_type in QualificationCertificateOCR.QUALIFICATION_TYPES:
            if qual_type in text_lower:
                return qual_type.upper()
        
        return None
    
    @staticmethod
    def extract_field_of_study(text: str) -> Optional[str]:
        """Extract field/stream of study"""
        lines = text.strip().split('\n')
        
        for line in lines:
            line = line.strip()
            
            field_patterns = [
                r'(?:in|of)\s+(computer science|engineering|commerce|science|arts|business|management|technology)',
                r'(?:specialization|major|stream)\s*:?\s*([A-Za-z\s]+)',
            ]
            
            for pattern in field_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_completion_year(text: str) -> Optional[str]:
        """Extract year of completion/passing"""
        lines = text.strip().split('\n')
        
        for line in lines:
            year_patterns = [
                r'(?:year|passed|completed|awarded|graduated)\s*:?\s*(\d{4})',
                r'\b(20\d{2}|19\d{2})\b',  # Any year between 1900-2099
            ]
            
            for pattern in year_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    year = match.group(1)
                    year_int = int(year)
                    if 1950 <= year_int <= 2030:  # Reasonable year range
                        return year
        
        return None
    
    @staticmethod
    def extract_grade_or_percentage(text: str) -> Optional[str]:
        """Extract grade, CGPA, or percentage"""
        lines = text.strip().split('\n')
        
        for line in lines:
            grade_patterns = [
                r'(?:cgpa|gpa)\s*:?\s*(\d+\.?\d*)',
                r'(?:percentage|marks)\s*:?\s*(\d+\.?\d*)%?',
                r'(?:grade|class)\s*:?\s*([A-Z][+\-]?)',
                r'(\d+\.?\d*)\s*(?:cgpa|gpa)',
                r'(\d+\.?\d*)%',
            ]
            
            for pattern in grade_patterns:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    return match.group(1)
        
        return None
    
    @staticmethod
    def process_qualification_certificate(file_bytes: bytes, filename: str) -> Dict:
        
        result = {
            'is_valid': False,
            'is_qualification_certificate': False,
            'student_name': None,
            'institution_name': None,
            'qualification_type': None,
            'field_of_study': None,
            'completion_year': None,
            'grade_or_percentage': None,
            'raw_text': '',
            'error': None
        }
        
        try:
            logger.info(f"[QUALIFICATION OCR] Processing certificate: {filename}")
            
            # Read image
            image = Image.open(io.BytesIO(file_bytes))
            
            if image.mode != 'RGB':
                image = image.convert('RGB')
            
            # Extract text
            text = QualificationCertificateOCR.extract_text_from_image(image)
            result['raw_text'] = text
            
            if not text.strip():
                result['error'] = 'No text could be extracted from the certificate'
                return result
            
            # Verify if it's a qualification certificate
            is_certificate = QualificationCertificateOCR.is_qualification_certificate(text)
            result['is_qualification_certificate'] = is_certificate
            
            if not is_certificate:
                result['error'] = 'Document does not appear to be a qualification certificate'
                return result
            
            # Extract information
            result['student_name'] = QualificationCertificateOCR.extract_student_name(text)
            result['institution_name'] = QualificationCertificateOCR.extract_institution_name(text)
            result['qualification_type'] = QualificationCertificateOCR.extract_qualification_type(text)
            result['field_of_study'] = QualificationCertificateOCR.extract_field_of_study(text)
            result['completion_year'] = QualificationCertificateOCR.extract_completion_year(text)
            result['grade_or_percentage'] = QualificationCertificateOCR.extract_grade_or_percentage(text)
            
            # Mark as valid if we extracted at least some key information
            if result['student_name'] or result['institution_name']:
                result['is_valid'] = True
            
            logger.info(f"[QUALIFICATION OCR] Extraction complete - Valid: {result['is_valid']}")
            return result
            
        except Exception as e:
            result['error'] = str(e)
            logger.error(f"[QUALIFICATION OCR] Error processing: {e}")
            return result


def validate_and_extract_qualification_certificate(file_bytes: bytes, filename: str) -> Tuple[bool, Dict]:
    """
    Convenience function to validate and extract qualification certificate information
    
    Returns:
        (success: bool, data: dict)
    """
    result = QualificationCertificateOCR.process_qualification_certificate(file_bytes, filename)
    
    if result['error']:
        return False, {'error': result['error'], 'raw_text': result.get('raw_text', '')}
    
    if not result['is_qualification_certificate']:
        return False, {'error': 'Uploaded document is not a qualification certificate', 'raw_text': result.get('raw_text', '')}
    
    return result['is_valid'], result
