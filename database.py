# database.py
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# --- CONFIGURATION ---
# UPDATE THIS with your actual pgAdmin password!
# Format: postgresql://username:password@localhost:5432/database_name
SQLALCHEMY_DATABASE_URL = "postgresql://postgres:imadali@localhost:5432/vuln_scanner_db"

# Create the engine (the connection)
engine = create_engine(SQLALCHEMY_DATABASE_URL)

# Create a session factory (to talk to the DB)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

# Dependency to get the database session in API requests
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()