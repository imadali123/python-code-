from fastapi import FastAPI, Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime
import models, schemas, database
from fastapi.responses import FileResponse
import reporting
import os

# 1. Create the database tables automatically if they don't exist
models.Base.metadata.create_all(bind=database.engine)

app = FastAPI(title="Vulnerability Scanner API")

# 2. Add CORS Middleware (Crucial for your HTML Dashboard)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows all origins (for development)
    allow_credentials=True,
    allow_methods=["*"],  # Allows all methods (POST, GET, etc.)
    allow_headers=["*"],
)

# 3. Database Dependency
def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

# --- API ENDPOINTS ---

@app.get("/")
def home():
    return {"message": "Vulnerability Scanner API is ready."}

# Endpoint 1: Create a New Scan Job
@app.post("/scans/", response_model=schemas.ScanJobResponse)
def create_scan(scan: schemas.ScanJobCreate, db: Session = Depends(get_db)):
    new_scan = models.ScanJob(
        targets=scan.targets,
        scan_type=scan.scan_type,
        status="Queued",
        started_at=datetime.utcnow()
    )
    db.add(new_scan)
    db.commit()
    db.refresh(new_scan)
    return new_scan

# Endpoint 2: Get Scan Status (Is it finished?)
@app.get("/scans/{scan_id}", response_model=schemas.ScanJobResponse)
def get_scan_status(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(models.ScanJob).filter(models.ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan

# Endpoint 3: Get Scan Results (The vulnerabilities found)
@app.get("/scans/{scan_id}/findings", response_model=list[schemas.FindingResponse])
def get_scan_findings(scan_id: int, db: Session = Depends(get_db)):
    results = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    return results

# Endpoint: Download PDF Report
@app.get("/scans/{scan_id}/report")
def download_report(scan_id: int, db: Session = Depends(get_db)):
    # 1. Get Scan Info
    scan = db.query(models.ScanJob).filter(models.ScanJob.scan_id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # 2. Get Findings
    findings = db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()

    # 3. Generate PDF
    pdf_path = reporting.generate_pdf(scan_id, scan.targets, findings)

    # 4. Return the file
    return FileResponse(pdf_path, media_type='application/pdf', filename=pdf_path)