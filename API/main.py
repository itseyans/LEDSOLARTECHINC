# main.py

from fastapi import FastAPI, Form, Depends, HTTPException, status
from fastapi.responses import RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from fastapi.responses import JSONResponse
from typing import Annotated
from pydantic import BaseModel
from database import supabase
import schemas


SECRET_KEY = "b!RP6+&vOnk:zr^g^xIBA,OS-3=aX&djiwOU@djtre*"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- PASSWORD & TOKEN SETUP ---

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- NEW PYDANTIC MODEL FOR STATUS UPDATES ---
class StatusUpdate(BaseModel):
    status: str

# --- UTILITY FUNCTIONS ---

def verify_password(plain_password, hashed_password):
    """Compares a plain text password with a stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generates a secure hash for a plain text password."""
    return pwd_context.hash(password)

def create_access_token(data: dict):
    """Creates a new JWT access token."""
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- FASTAPI APP INITIALIZATION ---

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- API ENDPOINTS ---

@app.get("/")
def read_root():
    """A simple root endpoint to confirm the API is running."""
    return {"message": "LEDSolarTech Inc. API is running."}


@app.post("/submit-form")
async def submit_form(form: schemas.ContactForm):
    """Handles submissions from the public contact form."""
    try:
        incoming_data = form.dict()
        allowed_columns = [
            "name", "email", "phone", "address", 
            "average_bill", "subject", "message"
        ]

        data_to_insert = {
            key: incoming_data.get(key) for key in allowed_columns
        }

        data, count = supabase.table("ContactForm").insert(data_to_insert).execute()

        if not data[1]:
            raise Exception("Failed to insert data into Supabase.")

    except Exception as e:
        print(f"Error submitting form: {e}")
        return JSONResponse(
            status_code=500, 
            content={"message": "An error occurred on the server.", "detail": str(e)}
        )

    return JSONResponse(status_code=200, content={"message": "Form submitted successfully!"})


@app.post("/create-password-hash/{password}")
def create_hash(password: str):
    """TEMPORARY endpoint to create a password hash for the admin user."""
    return {"hashed_password": get_password_hash(password)}


@app.post("/login")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Handles the admin login process."""
    data, count = supabase.table("AdminLogin").select("*").eq("username", form_data.username).execute()

    if not data[1]:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = data[1][0]

    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/admin/dashboard-stats")
async def get_dashboard_stats(token: Annotated[str, Depends(oauth2_scheme)]):
    """A Protected Endpoint (Example for your dashboard)."""
    return {"message": "Welcome, Admin! Here are your stats."}


@app.patch("/submissions/{submission_id}/status")
async def update_submission_status(
    submission_id: int,
    status_update: StatusUpdate,
    token: str = Depends(oauth2_scheme) 
):
    """
    Updates the status of a specific submission.
    """
    try:
        data, count = supabase.table("ContactForm").update({"status": status_update.status}).eq("id", submission_id).execute()
        
        if not data[1]:
            raise HTTPException(status_code=404, detail="Submission not found")

        return {"message": "Status updated successfully", "updated_submission": data[1][0]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/dashboard-data")
async def get_dashboard_data(token: Annotated[str, Depends(oauth2_scheme)]):
    """
    This is the secure endpoint for the admin dashboard.
    It requires a valid login token and fetches all data
    from the "ContactForm" table in Supabase.
    """
    try:
        data, count = supabase.table("ContactForm").select("*").order("created_at", desc=True).execute()

        return data[1]

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
