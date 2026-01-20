
from fpdf import FPDF
import os

class PDFReport(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Vulnerability Scan Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(scan_id, target, findings):
    pdf = PDFReport()
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # 1. Scan Summary
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, f"Target Scanned: {target}", 0, 1)
    pdf.set_font("Arial", size=12)
    pdf.cell(0, 10, f"Scan ID: {scan_id}", 0, 1)
    pdf.cell(0, 10, f"Total Vulnerabilities Found: {len(findings)}", 0, 1)
    pdf.ln(10)

    # 2. Findings Details
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(0, 10, "Detailed Findings:", 0, 1)
    pdf.ln(5)

    if not findings:
        pdf.set_font("Arial", 'I', 12)
        pdf.cell(0, 10, "No vulnerabilities detected.", 0, 1)
    else:
        for item in findings:
            # Title (Bold)
            pdf.set_font("Arial", 'B', 12)
            # Set color based on severity
            if item.severity == 'High':
                pdf.set_text_color(220, 53, 69) # Red
            elif item.severity == 'Medium':
                pdf.set_text_color(255, 193, 7) # Orange
            else:
                pdf.set_text_color(0, 128, 0)   # Green
            
            pdf.cell(0, 10, f"[{item.severity}] {item.title}", 0, 1)
            
            # Reset color to black for description
            pdf.set_text_color(0, 0, 0)
            pdf.set_font("Arial", size=11)
            pdf.multi_cell(0, 7, f"Description: {item.description}")
            pdf.ln(5)

    # 3. Save the file
    filename = f"scan_report_{scan_id}.pdf"
    pdf.output(filename)
    return filename