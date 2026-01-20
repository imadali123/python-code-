import time
import nmap
import json
from sqlalchemy.orm import Session
from database import SessionLocal, engine
import models

# Ensure tables exist
models.Base.metadata.create_all(bind=engine)

def perform_scan(scan_id, target, scan_type, db: Session):
    """
    The core logic of the scanner. We separated this so we can test it!
    """
    nm = nmap.PortScanner()
    
    # 1. Update Status to Running
    job = db.query(models.ScanJob).filter(models.ScanJob.scan_id == scan_id).first()
    job.status = "Running"
    db.commit()

    try:
        # 2. Run Nmap (Mock this in tests)
        print(f"Scanning {target}...")
        if scan_type == "Quick":
            nm.scan(target, arguments="-F") # Fast scan
        else:
            nm.scan(target, arguments="-sV --script=vuln") # Full scan
        
        # 3. Save Results
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    
                    # Create Finding
                    finding = models.Finding(
                        scan_id=scan_id,
                        title=f"Open Port {port} ({service['name']})",
                        description=f"Service: {service['product']} {service['version']}",
                        severity="Low" # Default to low for ports
                    )
                    
                    # Check for scripts (Vulnerabilities)
                    if 'script' in service:
                        for script_name, output in service['script'].items():
                            finding.title = f"VULN: {script_name}"
                            finding.description = output
                            finding.severity = "High"
                    
                    db.add(finding)
        
        # 4. Mark as Completed
        job.status = "Completed"
        db.commit()
        print(f"[+] Scan {scan_id} Completed.")

    except Exception as e:
        print(f"[-] Error: {e}")
        job.status = "Failed"
        db.commit()

def run_worker():
    """
    The infinite loop that waits for jobs.
    """
    print("Scanner Worker Started...")
    while True:
        db = SessionLocal()
        try:
            # Look for Queued jobs
            job = db.query(models.ScanJob).filter(models.ScanJob.status == "Queued").first()
            if job:
                print(f"[+] Found Job {job.scan_id}")
                perform_scan(job.scan_id, job.targets, job.scan_type, db)
            else:
                time.sleep(2)
        except Exception as e:
            print(e)
        finally:
            db.close()

if __name__ == "__main__":
    run_worker()