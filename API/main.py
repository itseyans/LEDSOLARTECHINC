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
# --- ADDED IMPORT ---
from pydantic import BaseModel

# Import your other modules
from database import supabase
import schemas

# --- SECURITY SETUP ---
# These constants are used for creating and verifying secure login tokens.

# Secret key to create and validate tokens (should be kept secret in a real production app)
SECRET_KEY = "b!RP6+&vOnk:zr^g^xIBA,OS-3=aX&djiwOU@djtre*"
# The encryption algorithm used for the JWT
ALGORITHM = "HS256"
# How long a login token is valid for
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# --- PASSWORD & TOKEN SETUP ---

# Setup for password hashing using bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Defines the security scheme. It tells FastAPI to look for a Bearer token
# in the Authorization header to access protected endpoints.
# The `tokenUrl="login"` points to your /login endpoint.
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# --- NEW PYDANTIC MODEL FOR STATUS UPDATES ---
class StatusUpdate(BaseModel):
    status: str

# --- UTILITY FUNCTIONS ---
# Helper functions for authentication.

def verify_password(plain_password, hashed_password):
    """Compares a plain text password with a stored hash."""
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    """Generates a secure hash for a plain text password."""
    return pwd_context.hash(password)

def create_access_token(data: dict):
    """Creates a new JWT access token."""
    to_encode = data.copy()
    # Set the token's expiration time
    expire = datetime.now(timezone.utc) + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    # Encode the token with your data, secret key, and algorithm
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- FASTAPI APP INITIALIZATION ---

# Create the main FastAPI application instance
app = FastAPI()

# --- Add CORS Middleware ---
# This is crucial for allowing your HTML/JavaScript frontend to communicate with this API.
# The "*" allows connections from any origin.
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


# === UPDATED AND FIXED: This endpoint now correctly accepts and processes JSON data ===
@app.post("/submit-form")
async def submit_form(form: schemas.ContactForm):
    """Handles submissions from the public contact form."""
    try:
        # Convert the incoming Pydantic model to a dictionary
        incoming_data = form.dict()

        # --- START OF CORRECTION ---
        # Define the exact columns your database table accepts.
        # This list should match your Supabase table columns.
        allowed_columns = [
            "name", "email", "phone", "address", 
            "average_bill", "subject", "message"
        ]

        # Create a new dictionary with only the allowed data.
        # This safely ignores any extra fields from the form, like 'accept'.
        data_to_insert = {
            key: incoming_data.get(key) for key in allowed_columns
        }
        # --- END OF CORRECTION ---

        # Insert the sanitized data into the 'ContactForm' table in Supabase
        data, count = supabase.table("ContactForm").insert(data_to_insert).execute()

        # Check if the insert was successful (for supabase-py v1)
        # The 'data' part of the response contains the inserted record.
        if not data[1]:
            raise Exception("Failed to insert data into Supabase.")

    except Exception as e:
        # If there's an error, print it and return a 500 error
        print(f"Error submitting form: {e}")
        return JSONResponse(
            status_code=500, 
            content={"message": "An error occurred on the server.", "detail": str(e)}
        )

    # Return a success message in JSON format
    return JSONResponse(status_code=200, content={"message": "Form submitted successfully!"})


@app.post("/create-password-hash/{password}")
def create_hash(password: str):
    """TEMPORARY endpoint to create a password hash for the admin user."""
    return {"hashed_password": get_password_hash(password)}


@app.post("/login")
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()]):
    """Handles the admin login process."""
    # Fetch the user from the database by username
    data, count = supabase.table("AdminLogin").select("*").eq("username", form_data.username).execute()

    # Check if a user was found
    if not data[1]:
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    user = data[1][0]

    # Verify the provided password against the stored hash
    if not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(status_code=400, detail="Incorrect username or password")

    # If credentials are correct, create and return a new access token
    access_token = create_access_token(data={"sub": user["username"]})
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/admin/dashboard-stats")
async def get_dashboard_stats(token: Annotated[str, Depends(oauth2_scheme)]):
    """A Protected Endpoint (Example for your dashboard)."""
    # This function will only run if a valid token is provided in the request header.
    # Here you would fetch data for your dashboard
    return {"message": "Welcome, Admin! Here are your stats."}


# --- CORRECTED ENDPOINT FOR UPDATING STATUS ---
@app.patch("/submissions/{submission_id}/status")
async def update_submission_status(
    submission_id: int,
    status_update: StatusUpdate,
    token: str = Depends(oauth2_scheme) # This keeps the endpoint secure
):
    """
    Updates the status of a specific submission.
    """
    try:
        # Update the row in the Supabase 'ContactForm' table (using v1 syntax)
        data, count = supabase.table("ContactForm").update({"status": status_update.status}).eq("id", submission_id).execute()
        
        # In supabase-py v1, check the returned data tuple
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
        # Fetches all records from your "ContactForm" table, ordered by newest first
        data, count = supabase.table("ContactForm").select("*").order("created_at", desc=True).execute()

        # In supabase-py v1, the result is a tuple (data, count).
        # We return the list of data, which is the second element.
        return data[1]

    except Exception as e:
        # If anything goes wrong during the database call, raise a server error
        raise HTTPException(status_code=500, detail=str(e))
