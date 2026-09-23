import os
import sys

# Ensure parent path is in sys.path for clean imports
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from models import Base, engine

def init_db():
    print("Creating database schema via SQLAlchemy...")
    db_file_path = engine.url.database
    os.makedirs(os.path.dirname(os.path.abspath(db_file_path)), exist_ok=True)
    
    # Create all tables defined in models.py
    Base.metadata.create_all(bind=engine)
    print("✅ All database tables created successfully!")

if __name__ == "__main__":
    init_db()