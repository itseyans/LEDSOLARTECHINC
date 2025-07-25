
from sqlalchemy.orm import Session
from . import models

def get_all_submissions(db: Session):
    return db.query(models.ContactForm).order_by(models.ContactForm.created_at.desc()).all()