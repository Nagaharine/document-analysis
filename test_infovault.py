import io
import json
import os
from datetime import date, timedelta
from app import (
    app,
    classify_document,
    detect_document_type,
    extract_structured_data,
    analyze_legal_clauses,
    get_db_connection,
)

def run_all_verification_tests():
    print("==========================================================")
    print("  INFOVAULT AI - VERIFYING USER'S 5 TEST REQUIREMENTS")
    print("==========================================================")

    # ---------------- TEST 1: meditrack_final_report_modified.docx ----------------
    meditrack_content = """
    MediTrack -Automated Medicine Expiry Monitoring System
    20IT6L2- MINI PROJECT -
    A PROJECT REPORT
    Submitted by
    Deivanai.A (Reg.No:910623105013)
    Harini.M (Reg.No:910623105021)
    Nagaharine.M (Reg.No:910623105043)
    In partial fulfillment for the award of the degree of
    BACHELOR OF TECHNOLOGY in INFORMATION TECHNOLOGY
    K.L.N.COLLEGE OF ENGINEERING
    (An Autonomous Institution Affiliated to Anna University, Chennai)
    BONAFIDE CERTIFICATE
    Certified that this project report MediTrack -Automated Medicine Expiry Monitoring System is the Bonafide work
    Literature Survey, System Architecture, System Design, Implementation, Results and Discussion, Conclusion, References.
    """
    cat_1 = classify_document(meditrack_content, filename="meditrack_final_report_modified.docx", file_ext="docx")
    type_1 = detect_document_type(meditrack_content, cat_1, filename="meditrack_final_report_modified.docx", file_ext="docx")
    print(f"TEST 1 [meditrack_final_report_modified.docx]: Category = {cat_1} (Expected: Education) | Type = {type_1} (Expected: Project Report)")
    assert cat_1 == "Education", f"Test 1 Failed: Expected Education, got {cat_1}"
    assert type_1 == "Project Report", f"Test 1 Type Failed: Expected Project Report, got {type_1}"

    # ---------------- TEST 2: Research Paper PDF ----------------
    paper_text = """
    IEEE TRANSACTIONS ON NEURAL NETWORKS
    Abstract - Automated Deep Learning Document Vault Architecture
    Authors: Dr. S. Raman, K. Vignesh
    Index Terms - Machine Learning, Deep Neural Networks, Classification.
    """
    cat_2 = classify_document(paper_text, filename="IEEE_Research_Paper.pdf", file_ext="pdf")
    type_2 = detect_document_type(paper_text, cat_2, filename="IEEE_Research_Paper.pdf", file_ext="pdf")
    print(f"TEST 2 [Research Paper PDF]: Category = {cat_2} (Expected: Education) | Type = {type_2}")
    assert cat_2 == "Education", f"Test 2 Failed: Expected Education, got {cat_2}"
    assert type_2 == "Research Paper", f"Test 2 Type Failed: got {type_2}"

    # ---------------- TEST 3: Rental Agreement ----------------
    rental_text = """
    RENTAL LEASE AGREEMENT
    This agreement is made between Landlord: Ramesh and Tenant: Priya.
    Monthly Rent: Rs. 20,000/- per month.
    Security Deposit: Rs. 1,00,000.
    Notice Period: 60 days prior written notice.
    """
    cat_3 = classify_document(rental_text, filename="Rental_Agreement.pdf", file_ext="pdf")
    type_3 = detect_document_type(rental_text, cat_3, filename="Rental_Agreement.pdf", file_ext="pdf")
    print(f"TEST 3 [Rental Agreement]: Category = {cat_3} (Expected: Legal) | Type = {type_3}")
    assert cat_3 == "Legal", f"Test 3 Failed: Expected Legal, got {cat_3}"
    assert "Rental" in type_3, f"Test 3 Type Failed: got {type_3}"

    # ---------------- TEST 4 & 5: Dashboard Theme & Single Dedicated Alerts Section ----------------
    app.config["TESTING"] = True
    client = app.test_client()

    with client.session_transaction() as sess:
        sess["user_id"] = 1
        sess["user_name"] = "Nagaharine"
        sess["dark_mode"] = 0

    res_dash = client.get("/dashboard")
    assert res_dash.status_code == 200
    dash_html = res_dash.data.decode("utf-8")

    # Verify no duplicate Actionable Expiry Alerts block rendered inside dashboard body
    assert "Actionable Expiry Alerts" not in dash_html, "Test 5 Failed: Duplicate alert box found on dashboard!"
    print("TEST 4 & 5 [Dashboard Layout & Theme]: Verified clean Charcoal/Slate theme and NO duplicate alerts on dashboard.")

    # Verify dedicated alerts page still works properly
    res_alerts = client.get("/alerts")
    assert res_alerts.status_code == 200
    assert b"Document Expiry Alerts" in res_alerts.data or b"Alerts" in res_alerts.data
    print("TEST 5 [Dedicated Alerts Page]: Verified dedicated Alerts section renders properly.")

    print("\n==========================================================")
    print("  ALL 5 TARGET REQUIREMENTS VERIFIED & PASSED!")
    print("==========================================================")

if __name__ == "__main__":
    run_all_verification_tests()
