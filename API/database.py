import os
from supabase import create_client, Client
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker

# Get your Supabase URL and Key from the environment variables
# It's a good practice to set these in your environment for security
# For now, you can hardcode them to get started
# Example: url: str = "YOUR_SUPABASE_URL"
url: str = "https://efzlntddxrwkltvlqucu.supabase.co"
key: str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6ImVmemxudGRkeHJ3a2x0dmxxdWN1Iiwicm9sZSI6ImFub24iLCJpYXQiOjE3NTI1MDg1MDMsImV4cCI6MjA2ODA4NDUwM30.kn1GgX0rxV1TSFvatF6QswmdaZJK5e7Iglpm6lfCS1k"

# Create the Supabase client
supabase: Client = create_client(url, key)

SQLALCHEMY_DATABASE_URL = "postgresql://postgres:Lstechadmin818!@db.efzlntddxrwkltvlqucu.supabase.co:5432/postgresres"

engine = create_engine(SQLALCHEMY_DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

Base = declarative_base()

# Dependency to get a DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()