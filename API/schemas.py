from pydantic import BaseModel
from typing import Optional
from fastapi import Form, Request

class ContactForm(BaseModel):
    name: str
    email: str
    phone: Optional[str] = None
    address: Optional[str] = None
    average_bill: Optional[str] = None
    subject: Optional[str] = None
    message: str
    accept: str

    # --- IMPORTANT: Add this helper method ---
    # This allows FastAPI to correctly map the form fields to the model
    @classmethod
    def as_form(
        cls,
        name: str = Form(...),
        email: str = Form(...),
        phone: Optional[str] = Form(None),
        address: Optional[str] = Form(None),
        average_bill: Optional[str] = Form(None),
        subject: Optional[str] = Form(None),
        message: str = Form(...),
        accept: str = Form(...)
    ):
        return cls(
            name=name,
            email=email,
            phone=phone,
            address=address,
            average_bill=average_bill,
            subject=subject,
            message=message,
            accept=accept
        )