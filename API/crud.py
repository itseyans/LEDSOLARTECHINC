
from sqlalchemy.orm import Session
from . import models

def get_all_submissions(db: Session):
    # Query all records from the ContactForm table, ordering by the newest first
    return db.query(models.ContactForm).order_by(models.ContactForm.created_at.desc()).all()