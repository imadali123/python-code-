-- Project: Cybersecurity Vulnerability Scanner
-- Based on SRS Data Requirements [Section 6]

-- 1. USERS TABLE
-- Handles User Classes [Section 2.3] and AuthZ [Section 3.7]
CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL, -- Store ONLY hashed passwords, never plaintext
    role VARCHAR(20) NOT NULL CHECK (role IN ('Admin', 'Analyst', 'DevOps', 'Viewer')), -- Roles defined in [Section 3.7 / FR-AuthZ-02]
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- 2. ASSETS TABLE
-- Stores network hosts and targets [Section 6 / Item 204]
CREATE TABLE assets (
    asset_id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL, -- Supports IPv4 and IPv6
    hostname VARCHAR(255),
    owner_id INT REFERENCES users(user_id), -- "Owner" field from [Item 204]
    criticality VARCHAR(20) DEFAULT 'Medium' CHECK (criticality IN ('Low', 'Medium', 'High', 'Critical')),
    os_type VARCHAR(100), -- To store OS guess from Discovery [FR-Discov-03]
    last_scan_time TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. CREDENTIALS TABLE
-- Stores encrypted auth info for Authenticated Scans [Section 3.2.4 / Item 207]
CREATE TABLE credentials (
    credential_id SERIAL PRIMARY KEY,
    owner_id INT REFERENCES users(user_id),
    cred_name VARCHAR(100) NOT NULL, -- Friendly name to identify the cred
    cred_type VARCHAR(20) NOT NULL CHECK (cred_type IN ('SSH', 'WinRM', 'SMB', 'HTTP_Basic', 'API_Token')),
    encrypted_data TEXT NOT NULL, -- MUST store encrypted blob here [FR-Auth-02]
    iv_vector VARCHAR(255), -- Initialization vector for encryption (optional but recommended)
    last_used TIMESTAMP
);

-- 4. SCAN JOBS TABLE
-- Tracks the execution of scans [Section 6 / Item 205]
CREATE TABLE scan_jobs (
    scan_id SERIAL PRIMARY KEY,
    created_by INT REFERENCES users(user_id),
    targets TEXT NOT NULL, -- Comma-separated IPs or CIDR blocks
    scan_type VARCHAR(50) NOT NULL CHECK (scan_type IN ('Quick', 'Full', 'Web', 'Compliance')),
    status VARCHAR(20) DEFAULT 'Queued' CHECK (status IN ('Queued', 'Running', 'Completed', 'Failed', 'Cancelled')),
    policy_config JSONB, -- Stores the specific policy/plugins used [Item 205]
    started_at TIMESTAMP,
    finished_at TIMESTAMP,
    duration_seconds INT
);

-- 5. FINDINGS (VULNERABILITIES) TABLE
-- Stores the actual scan results [Section 6 / Item 206]
CREATE TABLE findings (
    finding_id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES scan_jobs(scan_id) ON DELETE CASCADE,
    asset_id INT REFERENCES assets(asset_id) ON DELETE SET NULL,
    cve_id VARCHAR(50), -- e.g., CVE-2023-1234
    title VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('Info', 'Low', 'Medium', 'High', 'Critical')), -- CVSS mapping [FR-Risk-01]
    cvss_score DECIMAL(3, 1), -- e.g., 9.8
    remediation_steps TEXT, -- [Item 206]
    evidence TEXT, -- Output snippet proving the vuln
    status VARCHAR(20) DEFAULT 'New' CHECK (status IN ('New', 'Triaged', 'False Positive', 'Fixed')),
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP
);

-- 6. AUDIT LOGS TABLE
-- For Compliance and Security [Section 3.10 / FR-Audit-01]
CREATE TABLE audit_logs (
    log_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    action VARCHAR(255) NOT NULL, -- e.g., "Started Scan", "Deleted Asset"
    target_object VARCHAR(100), -- e.g., "Scan #45"
    ip_source VARCHAR(45), -- IP of the user performing action
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 7. REPORTS TABLE (Optional but useful)
-- Stores references to generated PDF/HTML reports [FR-Report-02]
CREATE TABLE reports (
    report_id SERIAL PRIMARY KEY,
    scan_id INT REFERENCES scan_jobs(scan_id),
    format VARCHAR(10) CHECK (format IN ('PDF', 'HTML', 'CSV')),
    file_path VARCHAR(500) NOT NULL, -- Path to storage (S3 or local)
    generated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- INDEXES for Performance
-- Helpful for the Dashboard queries [Section 3.4]
CREATE INDEX idx_findings_severity ON findings(severity);
CREATE INDEX idx_findings_status ON findings(status);
CREATE INDEX idx_scan_status ON scan_jobs(status);
CREATE INDEX idx_assets_ip ON assets(ip_address);