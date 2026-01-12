"""
Aadhaar Card OCR and Validation Module
Extracts information from uploaded Aadhaar card images/PDFs
Using EasyOCR (no Tesseract required)
"""

import re
import cv2
import numpy as np
from PIL import Image
import easyocr
import io
from typing import Dict, Optional, Tuple
import logging

logger = logging.getLogger(__name__)

_reader = None
_reader_loading = False

def get_ocr_reader():
    """Get or create EasyOCR reader instance"""
    global _reader, _reader_loading
    if _reader is None and not _reader_loading:
        _reader_loading = True
        logger.info("[OCR] Loading EasyOCR models (this may take a few seconds on first use)...")
        try:
            # Initialize with English only for faster loading
            # Hindi can be added if needed but increases load time
            _reader = easyocr.Reader(['en'], gpu=False, verbose=False)
            logger.info("[OCR] EasyOCR reader initialized successfully")
        except Exception as e:
            logger.error(f"[OCR] Failed to initialize reader: {e}")
            _reader_loading = False
            raise
        _reader_loading = False
    return _reader

class AadhaarOCR:
    """Extract and validate Aadhaar card information from images"""
    
    AADHAAR_PATTERN = r'\b\d{4}\s?\d{4}\s?\d{4}\b'
    
    AADHAAR_KEYWORDS = ['aadhaar', 'aadhar', 'government of india', 'unique identification', 'uidai', 'मेरा आधार मेरी पहचान']
    
    DOB_PATTERNS = [
        r'\b(?:DOB|Date of Birth|Birth)\s*:?\s*(\d{2}[-/]\d{2}[-/]\d{4})',
        r'\b(\d{2}[-/]\d{2}[-/]\d{4})\b'
    ]
    
    @staticmethod
    def preprocess_image(image: Image.Image) -> np.ndarray:
        """
        Preprocess image for better OCR accuracy
        """
        img_cv = cv2.cvtColor(np.array(image), cv2.COLOR_RGB2BGR)
        
        gray = cv2.cvtColor(img_cv, cv2.COLOR_BGR2GRAY)
        
        denoised = cv2.fastNlMeansDenoising(gray)
        
        thresh = cv2.adaptiveThreshold(
            denoised, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, 
            cv2.THRESH_BINARY, 11, 2
        )
        
        clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(8,8))
        enhanced = clahe.apply(thresh)
        
        return enhanced
    
    @staticmethod
    def extract_text_from_image(image: Image.Image) -> str:
        """
        Extract text from image using EasyOCR
        """
        try:
            logger.info("[OCR] Converting image to array...")
            # Convert PIL Image to numpy array (RGB format for EasyOCR)
            img_array = np.array(image.convert('RGB'))
            
            logger.info("[OCR] Getting OCR reader...")
            reader = get_ocr_reader()
            
            logger.info("[OCR] Reading text from image...")
            # Extract text using EasyOCR
            results = reader.readtext(img_array, detail=0)  # detail=0 returns only text
            
            # Combine all detected text
            text = '\n'.join(results)
            
            logger.info(f"[OCR] Extracted {len(text)} characters from image")
            return text
        except Exception as e:
            logger.error(f"[OCR] Error: {str(e)}")
            raise
    
    @staticmethod
    def extract_text_from_pdf(file_bytes: bytes) -> str:
        """
        Extract text from PDF file
        """
        try:
            images = convert_from_path(io.BytesIO(file_bytes))
            
            all_text = ""
            for image in images:
                text = AadhaarOCR.extract_text_from_image(image)
                all_text += text + "\n"
            
            return all_text
        except Exception as e:
            print(f"PDF Processing Error: {str(e)}")
            return ""
    
    @staticmethod
    def is_aadhaar_card(text: str) -> bool:
        """
        Verify if the document is an Aadhaar card
        """
        text_lower = text.lower()
        
        keyword_count = sum(1 for keyword in AadhaarOCR.AADHAAR_KEYWORDS 
                           if keyword in text_lower)
        
        has_aadhaar_number = bool(re.search(AadhaarOCR.AADHAAR_PATTERN, text))
        
        return keyword_count >= 1 or has_aadhaar_number
    
    @staticmethod
    def extract_aadhaar_number(text: str) -> Optional[str]:
        """
        Extract Aadhaar number from text
        """
        matches = re.findall(AadhaarOCR.AADHAAR_PATTERN, text)
        
        if matches:
            aadhaar = matches[0].replace(' ', '')
            return aadhaar
        
        return None
    
    @staticmethod
    def extract_name(text: str) -> Optional[str]:
        """
        Extract name from Aadhaar card text
        In Aadhaar cards, name typically appears on the first line (in Hindi or English)
        without any label like "Name:" or "नाम:"
        """
        lines = text.strip().split('\n')

        for i, line in enumerate(lines[:10]): 
            line = line.strip()

            if not line or len(line) < 3:
                continue
            
            skip_keywords = ['government', 'india', 'aadhaar', 'aadhar', 'unique', 'identification', 'uidai']
            if any(keyword in line.lower() for keyword in skip_keywords):
                continue

            if re.match(r'^[A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\s]{2,50}$', line):

                if ' ' in line or len(line) >= 5:
                    return line

            name_match = re.search(r'(?:Name|नाम)\s*:?\s*([A-Z\u0900-\u097F][A-Za-z\u0900-\u097F\s]{2,50})', line)
            if name_match:
                return name_match.group(1).strip()
        
        return None
    
    @staticmethod
    def extract_dob(text: str) -> Optional[str]:
        """
        Extract date of birth from text
        In Aadhaar cards, DOB typically appears on the second line after name
        """
        lines = text.strip().split('\n')
        
        for i, line in enumerate(lines[:15]):  
            line = line.strip()
            
            for pattern in AadhaarOCR.DOB_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if match:
                    dob = match.group(1) if match.lastindex else match.group(0)
                    dob = dob.replace('-', '/')
                    return dob
            
            standalone_date = re.search(r'\b(\d{2}[/-]\d{2}[/-]\d{4})\b', line)
            if standalone_date:
                dob = standalone_date.group(1).replace('-', '/')
                return dob
        
        return None
    
    @staticmethod
    def extract_gender(text: str) -> Optional[str]:
        """
        Extract gender from text
        In Aadhaar cards, gender typically appears on the third line after name and DOB
        Supports both English (Male/Female) and Hindi (पुरुष/महिला)
        """
        text_lower = text.lower()
        lines = text.strip().split('\n')
        
        for line in lines[:15]:
            line_lower = line.lower().strip()

            if 'female' in line_lower or 'f' == line_lower:
                return 'Female'
            elif 'male' in line_lower and 'female' not in line_lower:
                return 'Male'
            elif line_lower == 'm':
                return 'Male'
            elif 'transgender' in line_lower:
                return 'Transgender'
            
            if 'महिला' in line or 'स्त्री' in line:
                return 'Female'
            elif 'पुरुष' in line:
                return 'Male'
        
        if 'male' in text_lower and 'female' not in text_lower:
            return 'Male'
        elif 'female' in text_lower:
            return 'Female'
        elif 'transgender' in text_lower:
            return 'Transgender'
        
        return None
    
    @staticmethod
    def process_aadhaar_document(file_bytes: bytes, filename: str) -> Dict[str, any]:
        """
        Main function to process Aadhaar document and extract information
        
        Returns:
        {
            'is_valid': bool,
            'is_aadhaar': bool,
            'aadhaar_number': str or None,
            'name': str or None,
            'dob': str or None,
            'gender': str or None,
            'error': str or None
        }
        """
        result = {
            'is_valid': False,
            'is_aadhaar': False,
            'aadhaar_number': None,
            'name': None,
            'dob': None,
            'gender': None,
            'raw_text': '',
            'error': None
        }
        
        try:
            file_ext = filename.lower().split('.')[-1]
            
            if file_ext == 'pdf':
                image = Image.open(io.BytesIO(file_bytes))
                text = AadhaarOCR.extract_text_from_image(image)
            elif file_ext in ['jpg', 'jpeg', 'png']:
                image = Image.open(io.BytesIO(file_bytes))
                text = AadhaarOCR.extract_text_from_image(image)
            else:
                result['error'] = "Unsupported file format"
                return result
            
            result['raw_text'] = text
            
            result['is_aadhaar'] = AadhaarOCR.is_aadhaar_card(text)
            
            if not result['is_aadhaar']:
                result['error'] = "Document does not appear to be an Aadhaar card"
                return result
            
            result['aadhaar_number'] = AadhaarOCR.extract_aadhaar_number(text)
            result['name'] = AadhaarOCR.extract_name(text)
            result['dob'] = AadhaarOCR.extract_dob(text)
            result['gender'] = AadhaarOCR.extract_gender(text)
            
            result['is_valid'] = result['aadhaar_number'] is not None
            
            return result
            
        except Exception as e:
            result['error'] = f"Processing error: {str(e)}"
            return result


def validate_and_extract_aadhaar(file_bytes: bytes, filename: str) -> Tuple[bool, Dict]:
    """
    Convenience function to validate and extract Aadhaar information
    
    Returns:
        (success: bool, data: dict)
    """
    ocr = AadhaarOCR()
    result = ocr.process_aadhaar_document(file_bytes, filename)
    
    if result['error']:
        return False, {'error': result['error']}
    
    if not result['is_aadhaar']:
        return False, {'error': 'Uploaded document is not an Aadhaar card'}
    
    return result['is_valid'], result
