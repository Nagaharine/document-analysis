import hashlib
import html
import io
import json
import os
import re
from datetime import datetime, date, timedelta
from docx import Document
from flask import (
    Flask,
    flash,
    jsonify,
    redirect,
    render_template,
    render_template_string,
    request,
    send_file,
    send_from_directory,
    session,
    url_for,
)
import mysql.connector
from PIL import Image, ImageEnhance, ImageFilter
from pypdf import PdfReader
import pytesseract
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

# ---------------- TESSERACT OCR CONFIGURATION ----------------
pytesseract.pytesseract.tesseract_cmd = (
    r"C:\Program Files\Tesseract-OCR\tesseract.exe"
)

app = Flask(__name__)
app.secret_key = "infovault_secret_key_2026_enterprise_vault"

# File upload configuration
UPLOAD_FOLDER = "uploads"
ALLOWED_EXTENSIONS = {"pdf", "png", "jpg", "jpeg", "docx", "txt", "webp"}
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


# ---------------- DATABASE CONNECTION & SAFE MIGRATION ----------------

def get_db_connection():
    return mysql.connector.connect(
        host="localhost", user="root", password="root123", database="infovault"
    )


def init_db():
    """Safely checks and adds required columns to MySQL without data loss."""
    try:
        db = get_db_connection()
        cursor = db.cursor()

        # Check users table
        cursor.execute("DESCRIBE users")
        user_columns = [col[0] for col in cursor.fetchall()]

        user_fields = {
            "dark_mode": "TINYINT(1) DEFAULT 0",
            "expiry_alerts": "TINYINT(1) DEFAULT 1",
            "email_alerts": "TINYINT(1) DEFAULT 1",
            "reminder_days": "INT DEFAULT 7",
            "auto_classify": "TINYINT(1) DEFAULT 1",
            "ai_summary": "TINYINT(1) DEFAULT 1",
            "clause_detection": "TINYINT(1) DEFAULT 1",
            "language": "VARCHAR(10) DEFAULT 'en'",
            "two_factor_enabled": "TINYINT(1) DEFAULT 0",
            "summary_style": "VARCHAR(20) DEFAULT 'simple'",
            "doc_sort_order": "VARCHAR(20) DEFAULT 'latest'",
        }

        for field, definition in user_fields.items():
            if field not in user_columns:
                cursor.execute(f"ALTER TABLE users ADD COLUMN {field} {definition}")
                db.commit()

        # Check documents table
        cursor.execute("DESCRIBE documents")
        doc_columns = [col[0] for col in cursor.fetchall()]

        doc_fields = {
            "document_type": "VARCHAR(100) DEFAULT 'General Document'",
            "file_hash": "VARCHAR(64) DEFAULT NULL",
            "summary": "TEXT DEFAULT NULL",
            "extracted_data": "LONGTEXT DEFAULT NULL",
            "risk_clauses": "LONGTEXT DEFAULT NULL",
        }

        for field, definition in doc_fields.items():
            if field not in doc_columns:
                cursor.execute(f"ALTER TABLE documents ADD COLUMN {field} {definition}")
                db.commit()

        cursor.close()
        db.close()
    except Exception as e:
        print("Database migration check error:", e)


# Run DB initialization safely
init_db()


# ---------------- TEXT EXTRACTION (WITH ENHANCED OCR & PDF FALLBACK) ----------------

def extract_text_from_image_pil(image_obj):
    """Applies preprocessing (grayscale + contrast enhancement) and runs OCR."""
    try:
        # 1. Direct attempt
        text1 = pytesseract.image_to_string(image_obj).strip()
        
        # 2. Enhanced contrast attempt
        img_gray = image_obj.convert("L")
        enhancer = ImageEnhance.Contrast(img_gray)
        img_enhanced = enhancer.enhance(2.0)
        text2 = pytesseract.image_to_string(img_enhanced).strip()

        # Pick whichever gave better textual length
        return text2 if len(text2) > len(text1) else text1
    except Exception as e:
        print("Image OCR Error:", e)
        return ""


def extract_text_from_file(file_path):
    if not os.path.exists(file_path):
        return ""

    extension = file_path.rsplit(".", 1)[-1].lower()

    # 1. PDF Extraction (with Scanned Image fallback)
    if extension == "pdf":
        text = ""
        try:
            reader = PdfReader(file_path)
            for page in reader.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n"

            # If PDF contains little/no raw text (scanned document), extract embedded images and OCR them
            if len(text.strip()) < 50 and len(reader.pages) > 0:
                print(f"Scanned/Image PDF detected for {file_path}, running OCR on page images...")
                for page in reader.pages:
                    for img_obj in page.images:
                        try:
                            img = Image.open(io.BytesIO(img_obj.data))
                            ocr_t = extract_text_from_image_pil(img)
                            if ocr_t:
                                text += ocr_t + "\n"
                        except Exception:
                            pass
        except Exception as e:
            print("PDF extraction error:", e)

        return text.strip()

    # 2. DOCX Extraction
    elif extension == "docx":
        text = ""
        try:
            document = Document(file_path)
            for paragraph in document.paragraphs:
                if paragraph.text.strip():
                    text += paragraph.text + "\n"
            for table in document.tables:
                for row in table.rows:
                    row_text = " | ".join(cell.text.strip() for cell in row.cells if cell.text.strip())
                    if row_text:
                        text += row_text + "\n"
        except Exception as e:
            print("DOCX extraction error:", e)

        return text.strip()

    # 3. TXT Extraction
    elif extension == "txt":
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as file:
                return file.read().strip()
        except Exception as e:
            print("TXT extraction error:", e)
            return ""

    # 4. Image Files (JPG, PNG, WEBP, JPEG) - Enhanced OCR
    elif extension in ["jpg", "jpeg", "png", "webp"]:
        try:
            image = Image.open(file_path)
            return extract_text_from_image_pil(image)
        except Exception as e:
            print("Image OCR extraction error:", e)
            return ""

    return ""


# ---------------- SHA-256 HASH GENERATION ----------------

def calculate_file_hash(file_path):
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(65536), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()


# ---------------- ROBUST DOCUMENT CLASSIFICATION & TYPE DETECTION ----------------

def classify_document(text, filename="", file_ext=""):
    combined = (filename + " " + text).lower()
    text_lower = text.lower()
    
    # 6 Core Categories
    keywords = {
        "Legal": [
            "rental agreement", "rent agreement", "lease agreement", "tenancy agreement", "lease deed",
            "arbitration", "arbitration agreement", "contract", "legal notice", "terms and conditions",
            "landlord", "tenant", "lessor", "lessee", "demised premises", "security deposit", "monthly rent",
            "notice period", "lock-in period", "lock in period", "stamp paper", "affidavit", "power of attorney",
            "sale deed", "property deed", "conveyance", "non-disclosure", "nda", "confidentiality agreement",
            "employment contract", "appointment letter", "undertaking", "indemnity", "jurisdiction",
            "party of the first part", "party of the second part", "witnesseth", "covenants", "breach of contract",
            "copyright form", "copyright agreement", "license agreement", "sublet", "sublease", "legal clause",
            "dispute resolution", "arbitrator"
        ],
        "Education": [
            "project report", "final report", "technical report", "academic report", "mini project", "major project",
            "capstone project", "engineering project", "project documentation", "submitted by", "guided by", "supervisor",
            "internal examiner", "external examiner", "viva voce", "in partial fulfillment", "literature survey",
            "system design", "system architecture", "methodology", "implementation", "results and discussion",
            "conclusion", "references", "bachelor of technology", "bachelor of engineering", "master of technology",
            "master of engineering", "b.tech", "b.e", "m.tech", "thesis", "dissertation", "synopsis", "case study",
            "marksheet", "mark sheet", "grade sheet", "statement of marks", "grade card", "semester marks",
            "degree certificate", "conferred the degree", "bachelor of", "master of", "doctor of philosophy", "diploma in",
            "academic transcript", "consolidated marksheet", "transcript", "provisional certificate", "bonafide certificate",
            "student", "university", "college", "school", "institute", "department", "semester", "academic year",
            "cgpa", "gpa", "examination", "scorecard", "hall ticket", "admit card", "enrollment no", "register no", "roll no",
            "research paper", "abstract", "ieee", "journal", "conference paper", "publication", "proceedings of",
            "machine learning", "deep learning", "artificial intelligence", "neural network", "algorithm",
            "questions", "question paper", "test", "exam", "assignment", "syllabus", "curriculum", "course",
            "lab manual", "laboratory manual", "experiment", "computer science", "information technology", "engineering",
            "curriculum vitae", "resume", "education", "internship", "controller of examinations"
        ],
        "Financial": [
            "bank statement", "bank account", "account number", "account no", "a/c no", "statement of account",
            "closing balance", "opening balance", "credit", "debit", "transaction", "transactions", "reference no",
            "invoice", "tax invoice", "bill to", "ship to", "gstin", "gst", "total amount", "amount due", "subtotal",
            "payment receipt", "cash receipt", "money receipt", "voucher", "salary slip", "payslip", "pay stub", "net pay",
            "gross pay", "deductions", "basic pay", "loan agreement", "loan statement", "emi", "sanction letter",
            "form 16", "income tax return", "itr", "financial statement", "balance sheet", "interest rate", "ifsc", "branch"
        ],
        "Identity": [
            "aadhaar", "aadhar", "uidai", "unique identification authority", "government of india",
            "passport", "republic of india passport", "type p", "passport no",
            "driving licence", "driving license", "driver licence", "driver license", "licence to drive", "license to drive",
            "transport department", "union of india", "dl no", "dl number",
            "permanent account number", "income tax department", "pan card", "pan no",
            "voter id", "voter identity", "election commission", "epic no", "elector photo identity",
            "identity card", "id card", "identity document", "date of birth", "dob", "nationality", "id number"
        ],
    }

    scores = {cat: 0 for cat in keywords}

    # Score based on extracted text (weighted heavily)
    for cat, kw_list in keywords.items():
        for kw in kw_list:
            if kw in text_lower:
                # Longer phrases get higher weight
                weight = 3 if len(kw.split()) > 1 else 1
                scores[cat] += text_lower.count(kw) * weight

    # Supplement with filename clues (weighted 4)
    fname_clean = filename.lower().replace("_", " ").replace("-", " ")
    for cat, kw_list in keywords.items():
        for kw in kw_list:
            if kw in fname_clean:
                scores[cat] += 4

    max_category = max(scores, key=scores.get)

    # If reliable textual matches found
    if scores[max_category] > 0:
        return max_category

    # Check for Image / Photos category
    ext = file_ext.lower().replace(".", "")
    if ext in ["jpg", "jpeg", "png", "webp"]:
        # If it is an image and has very little or no structured text, classify as Image / Photos
        return "Image / Photos"

    return "Other"


def detect_document_type(text, category, filename="", file_ext=""):
    combined = (filename + " " + text).lower()
    text_lower = text.lower()
    ext = file_ext.lower().replace(".", "")

    if category == "Legal":
        if any(w in combined for w in ["rental agreement", "rent agreement", "tenancy agreement", "landlord", "monthly rent", "security deposit", "rental"]):
            return "Rental Agreement"
        elif any(w in combined for w in ["lease agreement", "lease deed", "lessor", "lessee"]):
            return "Lease Agreement"
        elif any(w in combined for w in ["arbitration", "arbitrator", "dispute resolution agreement"]):
            return "Arbitration Agreement"
        elif any(w in combined for w in ["non-disclosure", "nda", "confidentiality agreement", "proprietary information"]):
            return "Non-Disclosure Agreement (NDA)"
        elif any(w in combined for w in ["employment agreement", "employment contract", "offer letter", "appointment letter"]):
            return "Employment Contract"
        elif any(w in combined for w in ["copyright form", "copyright agreement", "copyright"]):
            return "Copyright Agreement"
        elif any(w in combined for w in ["power of attorney", "attorney in fact"]):
            return "Power of Attorney"
        elif any(w in combined for w in ["sale deed", "property deed", "conveyance deed"]):
            return "Sale Deed"
        elif any(w in combined for w in ["affidavit", "sworn statement", "deponent"]):
            return "Affidavit"
        elif any(w in combined for w in ["loan agreement", "borrower", "lender", "promissory note"]):
            return "Loan Agreement"
        return "Legal Agreement"

    elif category == "Education":
        if any(w in combined for w in ["project report", "final report", "mini project", "major project", "capstone project", "technical report", "academic report", "project documentation", "final_report", "project_report", "mini_project", "project work", "meditrack"]):
            return "Project Report"
        elif any(w in combined for w in ["thesis", "dissertation", "phd thesis", "master thesis"]):
            return "Thesis / Dissertation"
        elif any(w in combined for w in ["resume", "curriculum vitae", "curriculum-vitae", "resume_"]):
            return "Resume / CV"
        elif any(w in combined for w in ["lab manual", "laboratory manual", "course outline", "syllabus", "experiment", "lab_manual"]):
            return "Lab Manual / Syllabus"
        elif any(w in combined for w in ["marksheet", "mark sheet", "grade sheet", "statement of marks", "grade card", "semester marks"]):
            return "Marksheet"
        elif any(w in combined for w in ["degree certificate", "conferred the degree", "bachelor of", "master of", "doctor of philosophy", "diploma in", "course certificate"]):
            return "Degree Certificate"
        elif any(w in combined for w in ["transcript", "official transcript", "academic transcript", "consolidated marksheet"]):
            return "Academic Transcript"
        elif any(w in combined for w in ["question paper", "questions", "part a questions", "internal assessment", "exam paper", "test paper", "important questions"]):
            return "Question Paper / Test"
        elif any(w in combined for w in ["research paper", "abstract", "ieee", "journal of", "proceedings of", "conference paper"]):
            return "Research Paper"
        elif any(w in combined for w in ["hall ticket", "admit card", "examination pass", "exam hall ticket"]):
            return "Hall Ticket"
        elif any(w in combined for w in ["bonafide", "bonafide certificate", "student of our college"]):
            return "Bonafide Certificate"
        return "Educational Document"

    elif category == "Financial":
        if any(w in combined for w in ["bank statement", "account statement", "closing balance", "opening balance"]):
            return "Bank Statement"
        elif any(w in combined for w in ["tax invoice", "invoice", "invoice no", "bill to", "ship to", "gstin", "subtotal"]):
            return "Invoice"
        elif any(w in combined for w in ["payslip", "pay slip", "salary slip", "earnings", "net pay", "basic pay"]):
            return "Salary Slip"
        elif any(w in combined for w in ["receipt", "payment receipt", "cash receipt", "money receipt"]):
            return "Payment Receipt"
        elif any(w in combined for w in ["loan account", "loan statement", "emi", "sanction letter"]):
            return "Loan Statement"
        elif any(w in combined for w in ["form 16", "income tax return", "itr", "tax deduction", "assessment year"]):
            return "Tax Return / Form 16"
        return "Financial Document"

    elif category == "Identity":
        if any(w in combined for w in ["aadhaar", "aadhar", "uidai", "unique identification"]):
            return "Aadhaar Card"
        elif any(w in combined for w in ["driving licence", "driving license", "driver licence", "licence to drive", "transport department", "dl no"]):
            return "Driving License"
        elif any(w in combined for w in ["passport", "republic of india passport", "type p", "passport no"]):
            return "Passport"
        elif any(w in combined for w in ["permanent account number", "income tax department", "pan card", "pan no"]):
            return "PAN Card"
        elif any(w in combined for w in ["voter", "elector photo identity", "election commission", "epic no"]):
            return "Voter ID Card"
        return "Identity Card"

    elif category == "Image / Photos":
        if any(w in combined for w in ["wallpaper", "background", "photo", "pic", "image", "nature", "animal", "portrait", "camera"]):
            return "Photograph / Wallpaper"
        return "Photograph"

    return "General Document"


# ---------------- STRUCTURED INFORMATION EXTRACTION ----------------

def extract_structured_data(text, category, doc_type):
    data = {}

    def find_first(pattern, default="Not Found", flags=re.IGNORECASE):
        match = re.search(pattern, text, flags)
        if match:
            for g in match.groups():
                if g and g.strip():
                    cleaned_val = g.strip().split("\n")[0].strip()
                    if cleaned_val:
                        return cleaned_val
        return default

    if category == "Legal":
        data["Landlord / Owner"] = find_first(r"(?:landlord|lessor|owner|first party|party of the first part)[\s:]+([A-Za-z\s\.\,\'\(]+?)(?:,|\n|son of|daughter of|residing at|hereinafter)")
        data["Tenant / Lessee"] = find_first(r"(?:tenant|lessee|second party|party of the second part)[\s:]+([A-Za-z\s\.\,\'\(]+?)(?:,|\n|son of|daughter of|residing at|hereinafter)")
        data["Monthly Rent"] = find_first(r"(?:monthly rent|rent of|sum of Rs\.?|Rs\.?|INR|₹)[\s:]*([0-9\,]+)(?:[\s\/\-\.]*(?:per month|\/-|pm|monthly))")
        data["Security Deposit"] = find_first(r"(?:security deposit|deposit amount|advance amount|caution deposit)[\s\w:]*(?:Rs\.?|INR|₹)?[\s:]*([0-9\,]+)")
        data["Notice Period"] = find_first(r"(\d+\s*(?:month|months|day|days))\s*(?:prior\s*)?(?:written\s*)?notice")
        data["Lock-in Period"] = find_first(r"lock[\s\-]*in\s*period\s*of\s*(\d+\s*(?:month|months|year|years))")
        data["Agreement Start Date"] = find_first(r"(?:entered into on this|made on this|dated|commencing from|effective from|with effect from|start date|date of agreement)[\s:]*([0-9]{1,2}(?:st|nd|rd|th)?\s+(?:day\s+of\s+)?[A-Za-z]+[\s\,]+[0-9]{4}|[0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})")
        data["Agreement End Date / Expiry"] = find_first(r"(?:ending on|expires on|period of \d+ months ending|valid up to)[\s:]*([0-9]{1,2}(?:st|nd|rd|th)?\s+[A-Za-z]+[\s\,]+[0-9]{4}|[0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})")
        data["Property Address"] = find_first(r"(?:premises located at|schedule property|demised premises|property situated at|residing at)[\s:]+([A-Za-z0-9\s\,\-\#\/\.]{6,60})(?:\.|\n|\()")

    elif category == "Education":
        data["Student / Candidate Name"] = find_first(r"(?:name of the student|name of candidate|student name|name)[\s:]+([A-Za-z\s\.]{2,40})")
        data["Institution / University"] = find_first(r"(?:university|college|institute|school|academy)[\s:]*([A-Za-z\s\,\.]{3,50})")
        data["Course / Program"] = find_first(r"(?:bachelor of|master of|b\.tech|b\.e|m\.tech|b\.sc|b\.com|degree in|department of|course)[\s:]*([A-Za-z\s\,\.]{2,40})")
        data["Department / Branch"] = find_first(r"(?:department of|branch of|discipline)[\s:]*([A-Za-z\s\,\.]{2,40})")
        data["Year / Semester"] = find_first(r"(?:semester|year|academic year)[\s:]*([0-9IVXthndst\s\-]+)")
        data["Roll / Register Number"] = find_first(r"(?:roll no|reg\.?\s*no|registration no|enrollment no|hall ticket no|register no)[\s:]*([A-Za-z0-9\-\/]+)")
        data["CGPA / Percentage / Grade"] = find_first(r"(?:cgpa|gpa|percentage|total marks|grade)[\s:]*([0-9\.]+(?:\s*\/\s*10|\s*\/\s*100|%|[A-O\+]+)?)")
        data["Issue / Examination Date"] = find_first(r"(?:date of issue|issued on|exam held in|dated)[\s:]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4}|[A-Za-z]+\s+[0-9]{4})")

    elif category == "Financial":
        data["Account Holder / Customer"] = find_first(r"(?:account holder|customer name|client name|billed to)[\s:]+([A-Za-z\s\.]{2,40})")
        data["Account / Card Number"] = find_first(r"(?:account no|a\/c no|acc no|account number)[\s:]*([X\*\d\-\s]{6,25})")
        data["Total Amount / Balance"] = find_first(r"(?:total amount|grand total|net amount|amount payable|closing balance|net pay)[\s:]*(?:Rs\.?|INR|₹|\$)?[\s:]*([0-9\,\.]+)")
        data["Invoice / Statement Number"] = find_first(r"(?:invoice no|bill no|statement no|receipt no|ref no)[\s:]*([A-Za-z0-9\-\/]+)")
        data["Date / Statement Period"] = find_first(r"(?:invoice date|bill date|statement period|dated|date)[\s:]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4}|[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4})")
        data["Due Date"] = find_first(r"(?:due date|payment due|pay by)[\s:]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4}|[0-9]{1,2}\s+[A-Za-z]+\s+[0-9]{4})")

    elif category == "Identity":
        data["Full Name"] = find_first(r"(?:holder name|given name|name)[\s:]+([A-Za-z\s\.]{2,40})")
        data["Date of Birth (DOB)"] = find_first(r"(?:dob|date of birth|birth date)[\s:]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})")
        data["Document / ID Number"] = find_first(r"(?:dl\s*no|driving licence no|passport no|pan no|epic no|aadhaar no|id no)[\s:]*([A-Za-z0-9\s\-]{6,20})")
        data["Father / Spouse / Relation"] = find_first(r"(?:father['\s]*s\s*name|s\/o|d\/o|w\/o|husband['\s]*s\s*name)[\s:]+([A-Za-z\s\.]{2,40})")
        data["Validity / Expiry Date"] = find_first(r"(?:valid till|valid up to|expiry date|date of expiry)[\s:]*([0-9]{1,2}[\/\-\.][0-9]{1,2}[\/\-\.][0-9]{2,4})")

    elif category == "Image / Photos":
        data["Media Format"] = "Image / Photograph"
        data["Visual Asset Type"] = doc_type

    else:
        data["Identified Subject"] = find_first(r"(?:subject|title|re)[\s:]+([A-Za-z0-9\s\,\.\-]{3,60})")
        data["Document Reference"] = find_first(r"(?:ref|reference no|id)[\s:]*([A-Za-z0-9\-\/]+)")

    cleaned = {}
    for k, v in data.items():
        v_str = str(v).strip()
        cleaned[k] = v_str if v_str and v_str != "Not Found" else "Not Found"

    return cleaned


# ---------------- LEGAL DOCUMENT INTELLIGENCE ----------------

def analyze_legal_clauses(text, doc_type, language="en", summary_style="simple"):
    clauses = []
    text_lower = text.lower()

    # 1. Notice Period
    notice_match = re.search(r"(\d+\s*(?:months?|days?)\s*(?:prior\s*)?(?:written\s*)?notice[^\.\n]*)", text, re.IGNORECASE)
    if notice_match or "notice period" in text_lower or "notice" in text_lower:
        snippet = notice_match.group(1) if notice_match else "Party must provide written notice prior to termination."
        exp = "A mandatory written notice must be submitted before vacating or terminating the agreement." if language != "ta" else "ஒப்பந்தத்தை முடிவுக்கு கொண்டுவர குறிப்பிட்ட காலத்திற்கு முன் எழுத்துப்பூர்வ அறிவிப்பு வழங்க வேண்டும்."
        risk = "Vacating without serving the required notice period may lead to deposit forfeiture or extra rent penalty." if language != "ta" else "முன்கூட்டியே அறிவிப்பு கொடுக்காமல் வெளியேறினால் வைப்புத்தொகை இழப்பு அல்லது அபராதம் விதிக்கப்படலாம்."

        clauses.append({
            "title": "Notice Period & Vacation Terms",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "Medium",
            "badge_color": "warning",
            "recommendation": "Always submit vacation notice in writing and get written acknowledgement."
        })

    # 2. Rent Escalation
    escalation_match = re.search(r"((?:increase|escalat\w+|enhance\w+)[\w\s]*(?:by\s*)?(\d+%\s*|every\s*\d+\s*months?|after\s*11\s*months?)[^\.\n]*)", text, re.IGNORECASE)
    if escalation_match or any(w in text_lower for w in ["escalation", "increase of rent", "enhancement of rent", "5% increase", "10% increase"]):
        snippet = escalation_match.group(1) if escalation_match else "Rent shall be escalated by 5% to 10% after 11 months / 1 year."
        exp = "Rent will automatically increase by a specified percentage after the initial tenure." if language != "ta" else "ஒப்பந்த காலம் முடிந்த பின் வாடகை குறிப்பிட்ட சதவிகிதம் உயர்த்தப்படும்."
        risk = "Automatic escalation increases future recurring financial outlays." if language != "ta" else "ஒவ்வொரு ஆண்டும் வாடகை உயர்வு நிதிச்சுமையை அதிகரிக்கலாம்."

        clauses.append({
            "title": "Rent Escalation & Annual Increment",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "Medium",
            "badge_color": "warning",
            "recommendation": "Confirm whether the percentage hike is capped and aligns with market rates."
        })

    # 3. Security Deposit Deductions
    deposit_match = re.search(r"((?:security deposit|advance amount)[\w\s]*(?:refund\w*|deduct\w*|painting charges|damages)[^\.\n]*)", text, re.IGNORECASE)
    if deposit_match or any(w in text_lower for w in ["security deposit", "deduction", "painting charges", "damage charges"]):
        snippet = deposit_match.group(1) if deposit_match else "Security deposit will be refunded after deductions for painting, damages, and unpaid dues."
        exp = "Deposit is refundable upon lease termination, subject to deductions for maintenance or painting." if language != "ta" else "வீட்டைக் காலி செய்யும்போது பெயிண்டிங் மற்றும் சேதங்களுக்கான தொகையைக் கழித்துக் கொண்டு மீதி முன்பணம் திருப்பித் தரப்படும்."
        risk = "Unspecified painting and repair deductions may lead to disputes during deposit return." if language != "ta" else "நியாயமற்ற பெயிண்டிங் கட்டணங்கள் உங்கள் முன்பணத்தைக் குறைக்கலாம்."

        clauses.append({
            "title": "Security Deposit Refund & Deductions",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "High",
            "badge_color": "danger",
            "recommendation": "Document existing wall and fixture conditions with date-stamped photos upon move-in."
        })

    # 4. Lock-in Period
    lockin_match = re.search(r"((?:lock[\s\-]*in\s*period)[\w\s]*(?:of\s*)?(\d+\s*(?:months?|years?))[^\.\n]*)", text, re.IGNORECASE)
    if lockin_match or "lock-in" in text_lower or "lock in" in text_lower:
        snippet = lockin_match.group(1) if lockin_match else "Neither party can terminate the agreement during the initial lock-in period."
        exp = "Neither tenant nor landlord can terminate the agreement during the designated lock-in duration." if language != "ta" else "பூட்டுதல் காலத்தில் எந்த தரப்பினரும் ஒப்பந்தத்தை ரத்து செய்ய முடியாது."
        risk = "Early exit during lock-in may legally obligate you to pay the entire remaining lock-in period rent." if language != "ta" else "இந்த காலத்தில் வெளியேறினால் மீதமுள்ள மாதங்களின் வாடகையை செலுத்த நேரிடலாம்."

        clauses.append({
            "title": "Lock-In Period & Early Exit Penalty",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "High",
            "badge_color": "danger",
            "recommendation": "Ensure lock-in duration matches your planned stay."
        })

    # 5. Subletting Restriction
    sublet_match = re.search(r"((?:not\s*(?:assign|sublet|part\s*with)|shall\s*not\s*sublet)[\w\s\,\.\'\-]+)", text, re.IGNORECASE)
    if sublet_match or any(w in text_lower for w in ["sublet", "sub-let", "sublease", "commercial use"]):
        snippet = sublet_match.group(1) if sublet_match else "Tenant shall not sublet, assign, or use premises for commercial activities."
        exp = "The property is strictly for residential use and cannot be transferred or subleased to third parties." if language != "ta" else "வாடகைதாரர் வீட்டை மற்றவர்களுக்கு உள்வாடகைக்கு விடக்கூடாது."
        risk = "Unauthorized sharing or subletting could trigger instant lease termination." if language != "ta" else "மீறினால் உடனடியாக ஒப்பந்தம் ரத்து செய்யப்படலாம்."

        clauses.append({
            "title": "Subletting & Usage Restrictions",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "Low",
            "badge_color": "info",
            "recommendation": "Clarify guest stay limits with property owner in advance."
        })

    # 6. Dispute Resolution
    jurisdiction_match = re.search(r"((?:jurisdiction|arbitration|courts\s*of|disputes\s*shall\s*be\s*subject)[\w\s\,\.\'\-]+)", text, re.IGNORECASE)
    if jurisdiction_match or any(w in text_lower for w in ["jurisdiction", "arbitration", "dispute resolution"]):
        snippet = jurisdiction_match.group(1) if jurisdiction_match else "Any legal dispute shall be subject to the exclusive jurisdiction of local courts or arbitration."
        exp = "Disputes will be resolved via arbitration or in designated civil courts of the specified city." if language != "ta" else "சட்டரீதியான தகராறுகள் உள்ளூர் நீதிமன்றம் அல்லது நடுவர் தீர்ப்பாயம் மூலம் தீர்க்கப்படும்."
        risk = "Specifies legal forum; ensure the location is convenient." if language != "ta" else "நீதிமன்ற அதிகார வரம்பு தொலைவில் இருந்தால் சிரமம் ஏற்படலாம்."

        clauses.append({
            "title": "Dispute Resolution & Legal Jurisdiction",
            "snippet": snippet,
            "explanation": exp,
            "risk_level": "Low",
            "badge_color": "info",
            "recommendation": "Check that the jurisdiction city matches the property's physical location."
        })

    if not clauses:
        clauses.append({
            "title": "General Binding Agreement Terms",
            "snippet": "The parties agree to abide by all conditions stated herein.",
            "explanation": "Standard contractual agreement defining rights and obligations." if language != "ta" else "ஒப்பந்தத்தின் அனைத்து விதிகளையும் இரு தரப்பினரும் கடைபிடிக்க வேண்டும்.",
            "risk_level": "Low",
            "badge_color": "info",
            "recommendation": "Review all clauses thoroughly before signing."
        })

    if summary_style == "detailed":
        summary = f"This legal document is classified as {doc_type}. Key covenants include {len(clauses)} detected clauses governing term conditions, tenant liabilities, and legal obligations."
    else:
        summary = f"Identified as {doc_type}. Highlights {len(clauses)} key terms including notice expectations, financial covenants, and termination rights."

    if language == "ta":
        summary = f"இந்த ஆவணம் {doc_type} என வகைப்படுத்தப்பட்டுள்ளது. இதில் {len(clauses)} முக்கிய விதிமுறைகள் கண்டறியப்பட்டுள்ளன."

    return summary, clauses


def generate_general_summary(text, category, doc_type, language="en", summary_style="simple"):
    word_count = len(text.split())
    if category == "Education":
        return f"Educational record categorized as {doc_type}. Contains academic performance, credentials, or course documentation." if language != "ta" else f"இது கல்வித்துறை ஆவணம் ({doc_type})."
    elif category == "Financial":
        return f"Financial statement/invoice classified as {doc_type}. Details financial transactions, billing entries, and monetary balances." if language != "ta" else f"இது நிதித்துறை ஆவணம் ({doc_type})."
    elif category == "Identity":
        return f"Official personal identity document verified as {doc_type}. Contains identity registration information." if language != "ta" else f"இது அரசு அங்கீகாரம் பெற்ற அடையாள ஆவணம் ({doc_type})."
    elif category == "Image / Photos":
        return f"Visual photograph / image asset classified as {doc_type}." if language != "ta" else f"இது புகைப்பட அல்லது பட ஆவணம் ({doc_type})."
    else:
        return f"General vaulted document ({doc_type}) containing {word_count} words of indexed text." if language != "ta" else f"பொது ஆவணம் ({doc_type})."


# ---------------- SERVE UPLOADED FILES ----------------

@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)


# ---------------- CONTEXT PROCESSOR ----------------

@app.context_processor
def inject_global_vault_context():
    if "user_id" in session:
        try:
            db = get_db_connection()
            cursor = db.cursor(dictionary=True)
            cursor.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
            user_pref = cursor.fetchone() or {}

            reminder_threshold = user_pref.get("reminder_days", 30) or 30
            cursor.execute(
                """
                SELECT id, title, category, document_type, expiry_date, DATEDIFF(expiry_date, CURDATE()) as days_left 
                FROM documents 
                WHERE user_id = %s AND expiry_date IS NOT NULL AND expiry_date <= DATE_ADD(CURDATE(), INTERVAL %s DAY)
                ORDER BY expiry_date ASC
            """,
                (session["user_id"], reminder_threshold),
            )
            notifications = cursor.fetchall()
            cursor.close()
            db.close()

            return {
                "alert_count": len(notifications) if user_pref.get("expiry_alerts", 1) else 0,
                "nav_notifications": notifications if user_pref.get("expiry_alerts", 1) else [],
                "current_user_pref": user_pref,
            }
        except Exception as e:
            print("Context processor error:", e)
            return {"alert_count": 0, "nav_notifications": [], "current_user_pref": {}}

    return {"alert_count": 0, "nav_notifications": [], "current_user_pref": {}}


# ---------------- LOGIN, REGISTER, FORGOT PASSWORD, LOGOUT ----------------

@app.route("/", methods=["GET", "POST"])
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()

        if not email or not password:
            flash("Please enter both email and password!", "danger")
            return render_template("login.html")

        db = get_db_connection()
        cursor = db.cursor(dictionary=True)
        cursor.execute("SELECT id, name, password, dark_mode FROM users WHERE LOWER(email) = %s", (email,))
        user = cursor.fetchone()
        cursor.close()
        db.close()

        if user is None:
            flash("Wrong email! Account not found.", "danger")
            return render_template("login.html")

        if check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            session["dark_mode"] = user.get("dark_mode", 0)
            return redirect(url_for("dashboard"))
        else:
            flash("Incorrect password!", "danger")
            return render_template("login.html")

    return render_template("login.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not name or not email or not password or not confirm_password:
            flash("All fields are required!", "danger")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template("register.html")

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
        if cursor.fetchone():
            cursor.close()
            db.close()
            flash("Email already registered!", "danger")
            return render_template("register.html")

        hashed_password = generate_password_hash(password)
        cursor.execute(
            "INSERT INTO users (name, email, password, dark_mode, expiry_alerts, email_alerts, reminder_days, auto_classify, ai_summary, clause_detection, language, summary_style, doc_sort_order) VALUES (%s, %s, %s, 0, 1, 1, 7, 1, 1, 1, 'en', 'simple', 'latest')",
            (name, email, hashed_password),
        )
        db.commit()
        cursor.close()
        db.close()

        flash("Registration successful! You can now log in.", "success")
        return redirect(url_for("home"))

    return render_template("register.html")


@app.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        new_password = request.form.get("new_password", "").strip()
        confirm_password = request.form.get("confirm_password", "").strip()

        if not email or not new_password or not confirm_password:
            flash("All fields are required!", "danger")
            return render_template("forgot_password.html")

        if new_password != confirm_password:
            flash("Passwords do not match!", "danger")
            return render_template("forgot_password.html")

        db = get_db_connection()
        cursor = db.cursor()
        cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s", (email,))
        user = cursor.fetchone()

        if not user:
            cursor.close()
            db.close()
            flash("Email address not found in our system!", "danger")
            return render_template("forgot_password.html")

        hashed_password = generate_password_hash(new_password)
        cursor.execute("UPDATE users SET password = %s WHERE LOWER(email) = %s", (hashed_password, email))
        db.commit()
        cursor.close()
        db.close()

        flash("Password updated successfully! Please log in.", "success")
        return redirect(url_for("home"))

    return render_template("forgot_password.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "info")
    return redirect(url_for("home"))


# ---------------- REDESIGNED DASHBOARD ----------------

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for("home"))

    user_id = session["user_id"]
    search_query = request.args.get("search", "").strip()
    category_filter = request.args.get("category", "").strip()

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user_pref = cursor.fetchone() or {}

    sort_order = user_pref.get("doc_sort_order", "latest")
    order_by_clause = "ORDER BY uploaded_at DESC"
    if sort_order == "name":
        order_by_clause = "ORDER BY title ASC"
    elif sort_order == "expiry":
        order_by_clause = "ORDER BY (expiry_date IS NULL), expiry_date ASC"

    query = "SELECT * FROM documents WHERE user_id = %s"
    params = [user_id]

    if search_query:
        query += " AND (title LIKE %s OR category LIKE %s OR document_type LIKE %s OR extracted_text LIKE %s)"
        like_p = f"%{search_query}%"
        params.extend([like_p, like_p, like_p, like_p])

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    query += f" {order_by_clause}"

    cursor.execute(query, tuple(params))
    documents = cursor.fetchall()

    today = date.today()
    total_docs = len(documents)

    expired_count = 0
    expiring_soon_count = 0
    safe_count = 0

    expiring_soon_docs = []
    expired_docs = []

    for doc in documents:
        expiry = doc.get("expiry_date")
        if expiry:
            if isinstance(expiry, str):
                try:
                    expiry = datetime.strptime(expiry, "%Y-%m-%d").date()
                except ValueError:
                    expiry = None

        if expiry:
            days_left = (expiry - today).days
            doc["days_left"] = days_left

            if days_left < 0:
                doc["expiry_status"] = "Expired"
                doc["status_badge"] = "danger"
                expired_count += 1
                expired_docs.append(doc)
            elif days_left <= 30:
                doc["expiry_status"] = "Expiring Soon"
                doc["status_badge"] = "warning"
                expiring_soon_count += 1
                expiring_soon_docs.append(doc)
            else:
                doc["expiry_status"] = "Safe"
                doc["status_badge"] = "success"
                safe_count += 1
        else:
            doc["days_left"] = None
            doc["expiry_status"] = "No Expiry"
            doc["status_badge"] = "secondary"

        if not doc.get("document_type"):
            doc["document_type"] = "General Document"

    # 6 Core Categories with Totals
    categories = {
        "Legal": 0,
        "Education": 0,
        "Financial": 0,
        "Identity": 0,
        "Image / Photos": 0,
        "Other": 0,
    }

    cursor.execute(
        "SELECT category, COUNT(*) as cnt FROM documents WHERE user_id = %s GROUP BY category",
        (user_id,),
    )
    for row in cursor.fetchall():
        cat = row["category"]
        if cat in categories:
            categories[cat] = row["cnt"]
        else:
            categories["Other"] += row["cnt"]

    cursor.close()
    db.close()

    # Dynamic time-of-day greeting
    hour = datetime.now().hour
    if hour < 12:
        greeting = "Good Morning"
    elif hour < 17:
        greeting = "Good Afternoon"
    else:
        greeting = "Good Evening"

    return render_template(
        "dashboard.html",
        user_name=session.get("user_name", "User"),
        greeting=greeting,
        documents=documents,
        total_docs=total_docs,
        categories=categories,
        expired_count=expired_count,
        expiring_soon_count=expiring_soon_count,
        safe_count=safe_count,
        expiring_soon_docs=expiring_soon_docs,
        expired_docs=expired_docs,
        search_query=search_query,
        selected_category=category_filter,
    )


# ---------------- UPLOAD DOCUMENT (WITH ENHANCED AI CLASSIFICATION) ----------------

@app.route("/upload-document", methods=["POST"])
def upload_document():
    if "user_id" not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for("home"))

    if "file" not in request.files:
        flash("No file selected!", "danger")
        return redirect(url_for("dashboard"))

    file = request.files["file"]
    expiry_date = request.form.get("expiry_date") or None

    if file.filename == "":
        flash("No file selected!", "danger")
        return redirect(url_for("dashboard"))

    if not allowed_file(file.filename):
        flash("Invalid file format! Allowed formats: PDF, PNG, JPG, JPEG, DOCX, TXT, WEBP", "danger")
        return redirect(url_for("dashboard"))

    user_id = session["user_id"]
    filename = secure_filename(file.filename)
    timestamp = int(datetime.now().timestamp())
    saved_filename = f"{user_id}_{timestamp}_{filename}"
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], saved_filename)
    file.save(file_path)

    # 1. Compute SHA-256 Hash for Duplicate Check
    file_hash = calculate_file_hash(file_path)

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT id, title FROM documents WHERE user_id = %s AND file_hash = %s",
        (user_id, file_hash),
    )
    duplicate_doc = cursor.fetchone()

    if duplicate_doc:
        cursor.close()
        db.close()
        if os.path.exists(file_path):
            os.remove(file_path)
        flash(f"⚠️ Duplicate document detected! This file is identical to your existing document '{duplicate_doc['title']}' (Document #{duplicate_doc['id']}).", "warning")
        return redirect(url_for("dashboard"))

    # Fetch user AI settings
    cursor.execute("SELECT auto_classify, ai_summary, clause_detection, language, summary_style FROM users WHERE id = %s", (user_id,))
    user_settings = cursor.fetchone() or {
        "auto_classify": 1,
        "ai_summary": 1,
        "clause_detection": 1,
        "language": "en",
        "summary_style": "simple",
    }

    # 2. Extract text (with OCR fallback for images/scanned PDFs)
    extracted_text = extract_text_from_file(file_path)
    file_ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""

    # 3. Enhanced Automatic Classification & Specific Document Type Detection
    if user_settings.get("auto_classify", 1):
        category = classify_document(extracted_text, filename=filename, file_ext=file_ext)
        doc_type = detect_document_type(extracted_text, category, filename=filename, file_ext=file_ext)
    else:
        category = "Other"
        doc_type = "General Document"

    # 4. Structured Entity Extraction
    extracted_data_dict = extract_structured_data(extracted_text, category, doc_type)
    extracted_data_json = json.dumps(extracted_data_dict, ensure_ascii=False)

    # 5. Legal Intelligence & Summary
    summary_text = ""
    risk_clauses_json = "[]"

    if category == "Legal" and user_settings.get("clause_detection", 1):
        summary_text, clauses_list = analyze_legal_clauses(
            extracted_text,
            doc_type,
            language=user_settings.get("language", "en"),
            summary_style=user_settings.get("summary_style", "simple"),
        )
        risk_clauses_json = json.dumps(clauses_list, ensure_ascii=False)
    elif user_settings.get("ai_summary", 1):
        summary_text = generate_general_summary(
            extracted_text,
            category,
            doc_type,
            language=user_settings.get("language", "en"),
            summary_style=user_settings.get("summary_style", "simple"),
        )

    # 6. Save to Database
    query = """
        INSERT INTO documents
        (user_id, title, category, document_type, file_path, expiry_date, extracted_text, file_hash, summary, extracted_data, risk_clauses)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """

    cursor.execute(
        query,
        (
            user_id,
            filename,
            category,
            doc_type,
            saved_filename,
            expiry_date,
            extracted_text,
            file_hash,
            summary_text,
            extracted_data_json,
            risk_clauses_json,
        ),
    )

    db.commit()
    inserted_id = cursor.lastrowid
    cursor.close()
    db.close()

    flash(
        f"Document uploaded! Automatically classified as '{category}' ({doc_type}).",
        "success",
    )
    return redirect(url_for("document_details", document_id=inserted_id))


# ---------------- SAFE RECLASSIFY EXISTING DOCUMENTS ----------------

@app.route("/reclassify-documents", methods=["POST", "GET"])
def reclassify_documents():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT id, title, file_path, extracted_text FROM documents WHERE user_id = %s", (user_id,))
    docs = cursor.fetchall()

    reclassified_count = 0
    for d in docs:
        fp = os.path.join(app.config["UPLOAD_FOLDER"], d["file_path"])
        file_ext = d["file_path"].rsplit(".", 1)[-1].lower() if "." in d["file_path"] else ""
        
        # Fresh text extraction if file exists
        extracted_text = d.get("extracted_text") or ""
        if os.path.exists(fp):
            fresh_text = extract_text_from_file(fp)
            if len(fresh_text) >= len(extracted_text):
                extracted_text = fresh_text

        # Classify with enhanced keyword and OCR scoring
        category = classify_document(extracted_text, filename=d["title"], file_ext=file_ext)
        doc_type = detect_document_type(extracted_text, category, filename=d["title"], file_ext=file_ext)
        extracted_data_dict = extract_structured_data(extracted_text, category, doc_type)
        extracted_data_json = json.dumps(extracted_data_dict, ensure_ascii=False)

        summary_text = ""
        risk_clauses_json = "[]"
        if category == "Legal":
            summary_text, clauses_list = analyze_legal_clauses(extracted_text, doc_type)
            risk_clauses_json = json.dumps(clauses_list, ensure_ascii=False)
        else:
            summary_text = generate_general_summary(extracted_text, category, doc_type)

        update_cursor = db.cursor()
        update_cursor.execute(
            """
            UPDATE documents 
            SET category=%s, document_type=%s, extracted_text=%s, extracted_data=%s, summary=%s, risk_clauses=%s
            WHERE id=%s AND user_id=%s
        """,
            (category, doc_type, extracted_text, extracted_data_json, summary_text, risk_clauses_json, d["id"], user_id),
        )
        db.commit()
        update_cursor.close()
        reclassified_count += 1

    cursor.close()
    db.close()

    flash(f"✨ Successfully refreshed and re-classified {reclassified_count} vault documents with improved AI intelligence!", "success")
    return redirect(url_for("dashboard"))


# ---------------- DOCUMENT DETAILS PAGE ----------------

@app.route("/document/<int:document_id>")
def document_details(document_id):
    if "user_id" not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute(
        "SELECT * FROM documents WHERE id = %s AND user_id = %s",
        (document_id, user_id),
    )
    document = cursor.fetchone()
    cursor.close()
    db.close()

    if not document:
        flash("Document not found or access denied!", "danger")
        return redirect(url_for("dashboard"))

    today = date.today()
    expiry = document.get("expiry_date")
    if expiry:
        if isinstance(expiry, str):
            try:
                expiry = datetime.strptime(expiry, "%Y-%m-%d").date()
            except ValueError:
                expiry = None

    if expiry:
        days_left = (expiry - today).days
        document["days_left"] = days_left
        if days_left < 0:
            document["expiry_status"] = "Expired"
            document["status_badge"] = "danger"
        elif days_left <= 30:
            document["expiry_status"] = "Expiring Soon"
            document["status_badge"] = "warning"
        else:
            document["expiry_status"] = "Safe"
            document["status_badge"] = "success"
    else:
        document["days_left"] = None
        document["expiry_status"] = "No Expiry"
        document["status_badge"] = "secondary"

    extracted_data = {}
    if document.get("extracted_data"):
        try:
            extracted_data = json.loads(document["extracted_data"])
        except Exception:
            extracted_data = {}

    if not extracted_data and document.get("extracted_text"):
        cat = document.get("category", "Other")
        dtype = document.get("document_type", "General Document")
        extracted_data = extract_structured_data(document["extracted_text"], cat, dtype)

    risk_clauses = []
    if document.get("risk_clauses"):
        try:
            risk_clauses = json.loads(document["risk_clauses"])
        except Exception:
            risk_clauses = []

    if document.get("category") == "Legal" and not risk_clauses and document.get("extracted_text"):
        summary_text, clauses_list = analyze_legal_clauses(
            document["extracted_text"],
            document.get("document_type", "Legal Agreement"),
        )
        risk_clauses = clauses_list
        if not document.get("summary"):
            document["summary"] = summary_text

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], document["file_path"])
    file_size_kb = 0
    if os.path.exists(file_path):
        file_size_kb = round(os.path.getsize(file_path) / 1024, 1)

    file_ext = document["file_path"].rsplit(".", 1)[-1].lower() if "." in document["file_path"] else "pdf"

    return render_template(
        "document_details.html",
        doc=document,
        extracted_data=extracted_data,
        risk_clauses=risk_clauses,
        file_size_kb=file_size_kb,
        file_ext=file_ext,
    )


# ---------------- VIEW / INLINE PREVIEW DOCUMENT ----------------

@app.route("/view-document/<int:document_id>")
def view_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT file_path, title, extracted_text FROM documents WHERE id = %s AND user_id = %s",
        (document_id, session["user_id"]),
    )
    document = cursor.fetchone()
    cursor.close()
    db.close()

    if not document:
        return "Document not found!"

    full_path = os.path.join(app.config["UPLOAD_FOLDER"], document["file_path"])
    file_ext = (
        document["file_path"].rsplit(".", 1)[-1].lower()
        if "." in document["file_path"]
        else document["title"].rsplit(".", 1)[-1].lower()
    )

    # 1. IMAGES
    if file_ext in ["jpg", "jpeg", "png", "webp"]:
        if os.path.exists(full_path):
            mimetype = f"image/{file_ext}" if file_ext != "jpg" else "image/jpeg"
            return send_file(full_path, mimetype=mimetype)
        return "Image file not found on server!"

    # 2. PDF Preview
    elif file_ext == "pdf":
        if os.path.exists(full_path):
            return send_file(full_path, mimetype="application/pdf")

    # 3. DOCX Preview
    elif file_ext == "docx":
        if os.path.exists(full_path):
            try:
                doc = Document(full_path)
                paragraphs = [
                    f"<p>{html.escape(p.text.strip())}</p>"
                    for p in doc.paragraphs
                    if p.text.strip()
                ]
                document_text = "\n".join(paragraphs)
            except Exception:
                document_text = f"<p>{html.escape(document.get('extracted_text', ''))}</p>"
        else:
            document_text = f"<p>{html.escape(document.get('extracted_text', ''))}</p>"

        html_code = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { background: #ffffff; font-family: 'Segoe UI', Tahoma, sans-serif; padding: 24px; color: #1e293b; line-height: 1.6; }
                p { font-size: 15px; margin-bottom: 12px; }
            </style>
        </head>
        <body>
            {{ document_text | safe }}
        </body>
        </html>
        """
        return render_template_string(html_code, document_text=document_text)

    # 4. TXT Preview
    elif file_ext == "txt":
        text_content = ""
        if os.path.exists(full_path):
            with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                text_content = f.read()
        else:
            text_content = document.get("extracted_text", "")

        html_code = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <style>
                body { background: #ffffff; font-family: monospace; padding: 24px; white-space: pre-wrap; line-height: 1.6; color: #1e293b; }
            </style>
        </head>
        <body>{{ text }}</body>
        </html>
        """
        return render_template_string(html_code, text=text_content)

    if document.get("extracted_text"):
        return render_template_string(
            "<div style='padding: 20px; font-family: sans-serif; background: #fff;'><pre style='white-space: pre-wrap;'>{{ text }}</pre></div>",
            text=document["extracted_text"],
        )

    return "Preview not available for this file type."


# ---------------- DOWNLOAD DOCUMENT ----------------

@app.route("/download-document/<int:document_id>")
def download_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT file_path, title FROM documents WHERE id = %s AND user_id = %s",
        (document_id, session["user_id"]),
    )
    document = cursor.fetchone()
    cursor.close()
    db.close()

    if not document:
        flash("Document not found!", "danger")
        return redirect(url_for("my_documents"))

    return send_from_directory(
        app.config["UPLOAD_FOLDER"],
        document["file_path"],
        as_attachment=True,
        download_name=document["title"],
    )


# ---------------- DELETE DOCUMENT ----------------

@app.route("/delete-document/<int:document_id>")
def delete_document(document_id):
    if "user_id" not in session:
        return redirect(url_for("home"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute(
        "SELECT file_path FROM documents WHERE id = %s AND user_id = %s",
        (document_id, session["user_id"]),
    )
    document = cursor.fetchone()

    if not document:
        cursor.close()
        db.close()
        flash("Document not found!", "danger")
        return redirect(url_for("my_documents"))

    file_path = os.path.join(app.config["UPLOAD_FOLDER"], document["file_path"])
    if os.path.exists(file_path):
        try:
            os.remove(file_path)
        except Exception as e:
            print("File delete error:", e)

    cursor.execute(
        "DELETE FROM documents WHERE id = %s AND user_id = %s",
        (document_id, session["user_id"]),
    )
    db.commit()
    cursor.close()
    db.close()

    flash("Document deleted successfully!", "success")
    return redirect(url_for("dashboard"))


# ---------------- MY DOCUMENTS ----------------

@app.route("/my-documents")
def my_documents():
    if "user_id" not in session:
        flash("Please log in first!", "danger")
        return redirect(url_for("home"))

    search_query = request.args.get("search", "").strip()
    category_filter = request.args.get("category", "").strip()
    status_filter = request.args.get("status", "").strip()
    type_filter = request.args.get("type", "").strip()
    sort_by = request.args.get("sort", "latest").strip()

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    query = "SELECT * FROM documents WHERE user_id = %s"
    params = [session["user_id"]]

    if search_query:
        query += " AND (title LIKE %s OR category LIKE %s OR document_type LIKE %s OR extracted_text LIKE %s)"
        like_p = f"%{search_query}%"
        params.extend([like_p, like_p, like_p, like_p])

    if category_filter:
        query += " AND category = %s"
        params.append(category_filter)

    if type_filter:
        query += " AND document_type = %s"
        params.append(type_filter)

    if status_filter == "expired":
        query += " AND expiry_date IS NOT NULL AND expiry_date < CURDATE()"
    elif status_filter == "expiring_soon":
        query += " AND expiry_date IS NOT NULL AND expiry_date BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 30 DAY)"
    elif status_filter == "safe":
        query += " AND expiry_date IS NOT NULL AND expiry_date > DATE_ADD(CURDATE(), INTERVAL 30 DAY)"
    elif status_filter == "no_expiry":
        query += " AND expiry_date IS NULL"

    if sort_by == "name":
        query += " ORDER BY title ASC"
    elif sort_by == "expiry":
        query += " ORDER BY (expiry_date IS NULL), expiry_date ASC"
    elif sort_by == "oldest":
        query += " ORDER BY uploaded_at ASC"
    else:
        query += " ORDER BY uploaded_at DESC"

    cursor.execute(query, tuple(params))
    documents = cursor.fetchall()

    today = date.today()
    for doc in documents:
        expiry = doc.get("expiry_date")
        if expiry:
            if isinstance(expiry, str):
                try:
                    expiry = datetime.strptime(expiry, "%Y-%m-%d").date()
                except ValueError:
                    expiry = None

        if expiry:
            days_left = (expiry - today).days
            doc["days_left"] = days_left
            if days_left < 0:
                doc["expiry_status"] = "Expired"
                doc["status_badge"] = "danger"
            elif days_left <= 30:
                doc["expiry_status"] = "Expiring Soon"
                doc["status_badge"] = "warning"
            else:
                doc["expiry_status"] = "Safe"
                doc["status_badge"] = "success"
        else:
            doc["days_left"] = None
            doc["expiry_status"] = "No Expiry"
            doc["status_badge"] = "secondary"

        if not doc.get("document_type"):
            doc["document_type"] = "General Document"

    cursor.execute("SELECT DISTINCT category FROM documents WHERE user_id = %s", (session["user_id"],))
    categories = [row["category"] for row in cursor.fetchall() if row.get("category")]

    cursor.execute("SELECT DISTINCT document_type FROM documents WHERE user_id = %s AND document_type IS NOT NULL", (session["user_id"],))
    doc_types = [row["document_type"] for row in cursor.fetchall() if row.get("document_type")]

    cursor.close()
    db.close()

    return render_template(
        "my_documents.html",
        documents=documents,
        categories=categories,
        doc_types=doc_types,
        search_query=search_query,
        selected_category=category_filter,
        selected_status=status_filter,
        selected_type=type_filter,
        selected_sort=sort_by,
    )


# ---------------- ALERTS PAGE ----------------

@app.route("/alerts")
def alerts():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT reminder_days FROM users WHERE id = %s", (user_id,))
    user_data = cursor.fetchone() or {}
    reminder_days = user_data.get("reminder_days", 30) or 30

    query = """
        SELECT id, title, category, document_type, expiry_date, DATEDIFF(expiry_date, CURDATE()) as days_left 
        FROM documents 
        WHERE user_id = %s AND expiry_date IS NOT NULL AND expiry_date <= DATE_ADD(CURDATE(), INTERVAL %s DAY)
        ORDER BY expiry_date ASC
    """
    cursor.execute(query, (user_id, max(reminder_days, 30)))
    alerts_list = cursor.fetchall()

    expired_alerts = [a for a in alerts_list if a["days_left"] < 0]
    expiring_soon_alerts = [a for a in alerts_list if a["days_left"] >= 0]

    cursor.close()
    db.close()

    return render_template(
        "alerts.html",
        alerts=alerts_list,
        expired_alerts=expired_alerts,
        expiring_soon_alerts=expiring_soon_alerts,
        reminder_days=reminder_days,
    )


# ---------------- AI ANALYTICS PAGE ----------------

@app.route("/ai-analytics")
def ai_analytics():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)

    cursor.execute("SELECT * FROM documents WHERE user_id = %s", (user_id,))
    all_docs = cursor.fetchall()

    total_docs = len(all_docs)
    category_counts = {"Legal": 0, "Education": 0, "Financial": 0, "Identity": 0, "Image / Photos": 0, "Other": 0}
    type_counts = {}
    total_clauses_analyzed = 0
    high_risk_clauses = 0

    for d in all_docs:
        cat = d.get("category", "Other")
        category_counts[cat] = category_counts.get(cat, 0) + 1
        dtype = d.get("document_type", "General Document") or "General Document"
        type_counts[dtype] = type_counts.get(dtype, 0) + 1

        if d.get("risk_clauses"):
            try:
                clauses = json.loads(d["risk_clauses"])
                total_clauses_analyzed += len(clauses)
                high_risk_clauses += sum(1 for c in clauses if c.get("risk_level") == "High")
            except Exception:
                pass

    cursor.close()
    db.close()

    return render_template(
        "ai_analytics.html",
        total_docs=total_docs,
        category_counts=category_counts,
        type_counts=type_counts,
        total_clauses_analyzed=total_clauses_analyzed,
        high_risk_clauses=high_risk_clauses,
        documents=all_docs[:10],
    )


# ---------------- SETTINGS PAGE ----------------

@app.route("/settings")
def settings():
    if "user_id" not in session:
        return redirect(url_for("home"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    cursor.close()
    db.close()

    return render_template("settings.html", user=user)


# ---------------- UPDATE PROFILE, PASSWORD, PREFERENCES ----------------

@app.route("/update-profile", methods=["POST"])
def update_profile():
    if "user_id" not in session:
        return redirect(url_for("home"))

    name = request.form.get("name", "").strip()
    email = request.form.get("email", "").strip().lower()

    if not name or not email:
        flash("Name and email cannot be empty!", "danger")
        return redirect(url_for("settings"))

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute("SELECT id FROM users WHERE LOWER(email) = %s AND id != %s", (email, session["user_id"]))
    if cursor.fetchone():
        cursor.close()
        db.close()
        flash("Email is already in use by another account!", "danger")
        return redirect(url_for("settings"))

    cursor.execute("UPDATE users SET name = %s, email = %s WHERE id = %s", (name, email, session["user_id"]))
    db.commit()
    cursor.close()
    db.close()

    session["user_name"] = name
    flash("Profile information updated successfully!", "success")
    return redirect(url_for("settings"))


@app.route("/change-password", methods=["POST"])
def change_password():
    if "user_id" not in session:
        return redirect(url_for("home"))

    current_password = request.form.get("current_password", "").strip()
    new_password = request.form.get("new_password", "").strip()
    confirm_password = request.form.get("confirm_password", "").strip()

    if not current_password or not new_password or not confirm_password:
        flash("All password fields are required!", "danger")
        return redirect(url_for("settings"))

    if new_password != confirm_password:
        flash("New passwords do not match!", "danger")
        return redirect(url_for("settings"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT password FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()

    if not user or not check_password_hash(user["password"], current_password):
        cursor.close()
        db.close()
        flash("Current password is incorrect!", "danger")
        return redirect(url_for("settings"))

    hashed_password = generate_password_hash(new_password)
    cursor.execute("UPDATE users SET password = %s WHERE id = %s", (hashed_password, session["user_id"]))
    db.commit()
    cursor.close()
    db.close()

    flash("Password changed successfully!", "success")
    return redirect(url_for("settings"))


@app.route("/toggle-2fa", methods=["POST"])
def toggle_2fa():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Not authenticated"}), 401

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT two_factor_enabled FROM users WHERE id = %s", (session["user_id"],))
    user = cursor.fetchone()
    current_status = user.get("two_factor_enabled", 0) if user else 0
    new_status = 0 if current_status else 1

    cursor.execute("UPDATE users SET two_factor_enabled = %s WHERE id = %s", (new_status, session["user_id"]))
    db.commit()
    cursor.close()
    db.close()

    flash(f"Two-Factor Authentication is now {'enabled' if new_status else 'disabled'}.", "success")
    return redirect(url_for("settings"))


@app.route("/save-preferences", methods=["POST"])
def save_preferences():
    if "user_id" not in session:
        return redirect(url_for("home"))

    dark_mode = 1 if request.form.get("dark_mode") in ["on", "1", "true"] else 0
    expiry_alerts = 1 if request.form.get("expiry_alerts") in ["on", "1", "true"] else 0
    email_alerts = 1 if request.form.get("email_alerts") in ["on", "1", "true"] else 0
    reminder_days = int(request.form.get("reminder_days", 7))
    auto_classify = 1 if request.form.get("auto_classify") in ["on", "1", "true"] else 0
    ai_summary = 1 if request.form.get("ai_summary") in ["on", "1", "true"] else 0
    clause_detection = 1 if request.form.get("clause_detection") in ["on", "1", "true"] else 0
    language = request.form.get("language", "en")
    summary_style = request.form.get("summary_style", "simple")
    doc_sort_order = request.form.get("doc_sort_order", "latest")

    db = get_db_connection()
    cursor = db.cursor()
    cursor.execute(
        """
        UPDATE users 
        SET dark_mode=%s, expiry_alerts=%s, email_alerts=%s, reminder_days=%s, 
            auto_classify=%s, ai_summary=%s, clause_detection=%s, language=%s,
            summary_style=%s, doc_sort_order=%s
        WHERE id=%s
    """,
        (
            dark_mode,
            expiry_alerts,
            email_alerts,
            reminder_days,
            auto_classify,
            ai_summary,
            clause_detection,
            language,
            summary_style,
            doc_sort_order,
            session["user_id"],
        ),
    )
    db.commit()
    cursor.close()
    db.close()

    session["dark_mode"] = dark_mode
    flash("Preferences saved successfully!", "success")
    return redirect(url_for("settings"))


@app.route("/download-my-data")
def download_my_data():
    if "user_id" not in session:
        return redirect(url_for("home"))

    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT id, name, email, dark_mode, language, summary_style, reminder_days FROM users WHERE id = %s", (session["user_id"],))
    user_info = cursor.fetchone()

    cursor.execute("SELECT id, title, category, document_type, expiry_date, uploaded_at, file_hash, summary, extracted_data FROM documents WHERE user_id = %s", (session["user_id"],))
    docs = cursor.fetchall()
    cursor.close()
    db.close()

    for d in docs:
        if isinstance(d.get("expiry_date"), (date, datetime)):
            d["expiry_date"] = str(d["expiry_date"])
        if isinstance(d.get("uploaded_at"), (date, datetime)):
            d["uploaded_at"] = str(d["uploaded_at"])

    return jsonify({"export_date": datetime.now().isoformat(), "user_profile": user_info, "vault_documents": docs})


@app.route("/delete-all-documents", methods=["POST"])
def delete_all_documents():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT file_path FROM documents WHERE user_id = %s", (user_id,))
    docs = cursor.fetchall()

    for d in docs:
        fp = os.path.join(app.config["UPLOAD_FOLDER"], d["file_path"])
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except Exception:
                pass

    cursor.execute("DELETE FROM documents WHERE user_id = %s", (user_id,))
    db.commit()
    cursor.close()
    db.close()

    flash("All documents have been permanently removed from your vault.", "info")
    return redirect(url_for("settings"))


@app.route("/delete-account", methods=["POST"])
def delete_account():
    if "user_id" not in session:
        return redirect(url_for("home"))

    user_id = session["user_id"]
    db = get_db_connection()
    cursor = db.cursor(dictionary=True)
    cursor.execute("SELECT file_path FROM documents WHERE user_id = %s", (user_id,))
    docs = cursor.fetchall()

    for d in docs:
        fp = os.path.join(app.config["UPLOAD_FOLDER"], d["file_path"])
        if os.path.exists(fp):
            try:
                os.remove(fp)
            except Exception:
                pass

    cursor.execute("DELETE FROM documents WHERE user_id = %s", (user_id,))
    cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    db.commit()
    cursor.close()
    db.close()

    session.clear()
    flash("Your account and all associated documents have been permanently deleted.", "info")
    return redirect(url_for("home"))


@app.route("/logout-all-devices", methods=["POST"])
def logout_all_devices():
    session.clear()
    flash("Successfully logged out from all active sessions.", "info")
    return redirect(url_for("home"))


if __name__ == "__main__":
    app.run(debug=True, port=5000)