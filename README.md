 Project Overview

This project is a Python-based vulnerability scanner that automates the process of network reconnaissance. It uses Nmap for scanning, FastAPI for the backend API, SQLite for data storage, and ReportLab for generating professional PDF reports.

The system is designed with a Microservices-lite architecture, separating the API (Frontend) from the Scanner Worker (Backend) for better performance.

 Key Features

Create Scans: Submit IP addresses/targets for scanning via API.

Async Processing: Uses a background worker to handle long-running Nmap scans without freezing the server.

PDF Reporting: Automatically generates a detailed PDF report with color-coded severity levels (High/Medium/Low).

Test Coverage: Fully automated test suite with >95% code coverage using pytest.

    Installation Requirements
1. Install Nmap

Windows: Download and install from nmap.org.

Ensure Nmap is added to your System PATH.

2. Install Python Dependencies Open your terminal in the project folder and run:


pip install fastapi uvicorn python-nmap sqlalchemy reportlab pytest pytest-cov httpx

  How to Run the Project
You need to open two separate terminals to run the full system.

Terminal 1: The API Server
This handles user requests and the database.

uvicorn main:app --reload

The API will be available at: http://127.0.0.1:8000

Interactive Documentation (Swagger UI): http://127.0.0.1:8000/docs

Terminal 2: The Scanner Worker
This performs the actual Nmap scans in the background.

python scanner_worker.py

You should see: Scanner Worker Started...

 How to Run Tests (Verification)

 This project includes a comprehensive test suite covering API endpoints, database logic, and the scanning worker (via Mocking).

Run all tests:


pytest

Generate Coverage Report (HTML):


pytest --cov=. --cov-report=html

Open htmlcov/index.html to view the detailed coverage report.


 Project Structure

main.py - FastAPI application and endpoints.

scanner_worker.py - Background script that runs Nmap.

models.py - Database tables (SQLAlchemy).

schemas.py - Pydantic models for API validation.

reporting.py - Logic for generating PDF files.

test_advanced.py - Automated tests with mocking.