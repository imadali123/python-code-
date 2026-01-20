import pytest
from fastapi.testclient import TestClient
from unittest.mock import MagicMock, patch
from main import app
from database import SessionLocal, Base, engine
import models
import scanner_worker
import reporting

# Setup Test Client
client = TestClient(app)

@pytest.fixture(scope="module")
def test_db():
    """Creates a temporary database connection for testing."""
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()
    yield db
    db.close()

# --- TEST 1: API SUCCESS (Happy Path) ---
def test_create_scan():
    response = client.post("/scans/", json={"targets": "127.0.0.1", "scan_type": "Quick"})
    assert response.status_code == 200
    assert response.json()["status"] == "Queued"

def test_get_scan_404():
    response = client.get("/scans/999999")
    assert response.status_code == 404

def test_get_scan_status_success():
    """Test getting a valid scan status"""
    res = client.post("/scans/", json={"targets": "10.10.10.10", "scan_type": "Quick"})
    scan_id = res.json()["scan_id"]
    res_get = client.get(f"/scans/{scan_id}")
    assert res_get.status_code == 200
    assert res_get.json()["targets"] == "10.10.10.10"

# --- TEST 2: WORKER SUCCESS (Mocking Real Nmap) ---
@patch("scanner_worker.nmap.PortScanner")
def test_worker_success(mock_nmap_cls, test_db):
    """Test a successful scan with vulnerabilities found."""
    # 1. Create Job
    job = models.ScanJob(targets="192.168.1.1", scan_type="Quick", status="Queued")
    test_db.add(job)
    test_db.commit()
    test_db.refresh(job)

    # 2. Mock Nmap complex object
    mock_nmap = mock_nmap_cls.return_value
    mock_nmap.all_hosts.return_value = ["192.168.1.1"]
    
    mock_host = MagicMock()
    mock_host.all_protocols.return_value = ["tcp"]
    mock_proto = MagicMock()
    mock_proto.keys.return_value = [80]
    
    mock_nmap.__getitem__.return_value = mock_host
    mock_host.__getitem__.return_value = mock_proto
    mock_proto.__getitem__.return_value = {
        "name": "http", "product": "Apache", "version": "2.4",
        "script": {"vuln-test": "Critical Error!"}
    }

    # 3. Run Worker
    scanner_worker.perform_scan(job.scan_id, job.targets, job.scan_type, test_db)

    # 4. Verify Success
    test_db.refresh(job)
    assert job.status == "Completed"
    
    findings = test_db.query(models.Finding).filter(models.Finding.scan_id == job.scan_id).all()
    assert len(findings) > 0

# --- TEST 3: WORKER FAILURE (Fixed) ---
def test_worker_failure(test_db):
    """Test what happens when Nmap crashes (Exception Handling)."""
    # 1. Create Job
    job = models.ScanJob(targets="10.0.0.99", scan_type="Quick", status="Queued")
    test_db.add(job)
    test_db.commit()
    test_db.refresh(job)

    # 2. Force Nmap to crash correctly
    # We allow the CLASS to load, but force the .scan() method to fail.
    # This ensures the crash happens INSIDE the try/except block.
    with patch("scanner_worker.nmap.PortScanner") as mock_cls:
        mock_instance = mock_cls.return_value
        mock_instance.scan.side_effect = Exception("Nmap Crashed!")
        
        scanner_worker.perform_scan(job.scan_id, job.targets, job.scan_type, test_db)
    
    # 3. Verify the code caught the error
    test_db.refresh(job)
    assert job.status == "Failed" 

# --- TEST 4: WORKER LOOP ENTRY (Fixed - No more hanging!) ---
@patch("scanner_worker.SessionLocal")
@patch("scanner_worker.time.sleep")
def test_worker_loop_entry(mock_sleep, mock_db_cls):
    """Test the main loop. We force it to crash with KeyboardInterrupt to break the infinite loop."""
    
    # Logic: 
    # 1. Worker starts -> gets DB
    # 2. DB returns None (no jobs) -> Code goes to 'else: time.sleep(2)'
    # 3. time.sleep() raises KeyboardInterrupt -> This breaks the 'while True' loop immediately.
    
    mock_db = MagicMock()
    mock_db_cls.return_value = mock_db
    
    # Setup query to return None (no jobs found)
    mock_db.query.return_value.filter.return_value.first.return_value = None
    
    # Make sleep raise KeyboardInterrupt. 
    # Normal 'Exception' is caught by the worker, but 'KeyboardInterrupt' is NOT, so it escapes.
    mock_sleep.side_effect = KeyboardInterrupt
    
    try:
        scanner_worker.run_worker()
    except KeyboardInterrupt:
        pass # Expected exit
    
    assert mock_sleep.called # Proves we entered the loop and hit the sleep line

# --- TEST 5: REPORTING COVERAGE ---
def test_pdf_generation_full_coverage():
    """Hit all colors (Red, Yellow, Green) in PDF generator."""
    findings = [
        MagicMock(severity="High", title="A", description="A"),
        MagicMock(severity="Medium", title="B", description="B"),
        MagicMock(severity="Low", title="C", description="C")
    ]
    name = reporting.generate_pdf(101, "1.1.1.1", findings)
    assert name.endswith(".pdf")
    
    # Empty case
    reporting.generate_pdf(102, "1.1.1.1", [])