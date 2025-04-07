# main.py
import os
from datetime import datetime, timedelta, timezone
from typing import Annotated, Optional

# --- Core FastAPI and Pydantic ---
from fastapi import Depends, FastAPI, HTTPException, status
from pydantic import BaseModel

# --- Security: Passwords & JWT ---
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext # For password hashing
import jwt # PyJWT library for handling tokens
from jwt.exceptions import InvalidTokenError # Specific exception from PyJWT

# --------------------------------------------------------------------------
# Configuration - WARNING: Hardcoded Secrets!
# In a real app, load these from environment variables / config files.
# --------------------------------------------------------------------------
# This key should be kept secret and be a long, random string.
# Generate one using: openssl rand -hex 32
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7" # <<<--- VERY INSECURE TO HARDCODE!
ALGORITHM = "HS256" # The signing algorithm for JWT
ACCESS_TOKEN_EXPIRE_MINUTES = 30 # How long the access token is valid

# --------------------------------------------------------------------------
# Pydantic Models (Data Shapes)
# --------------------------------------------------------------------------
class Token(BaseModel):
    """ Pydantic model for the response when issuing a token """
    access_token: str
    token_type: str

class TokenData(BaseModel):
    """ Pydantic model for the data hidden inside the JWT token """
    username: str | None = None

class User(BaseModel):
    """ Pydantic model for basic user information (safe to return in API) """
    username: str
    email: str | None = None
    full_name: str | None = None
    disabled: bool | None = None

class UserInDB(User):
    """ Pydantic model representing a user as stored (including hashed password) """
    hashed_password: str

# --------------------------------------------------------------------------
# Fake Database (Temporary!)
# Replace this with actual database interactions later.
# The password 'secret' for johndoe is hashed below.
# You can generate hashes using the get_password_hash function (see bottom)
# --------------------------------------------------------------------------
fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        # Hashed version of the password "secret" using bcrypt
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW",
        "disabled": False,
    },
     "coach_bob": {
        "username": "coach_bob",
        "full_name": "Coach Bob",
        "email": "bob@example.com",
        # Generate hash for password "password123" (example)
        # Run: print(get_password_hash("password123"))
        # Replace below hash with the generated one
        "hashed_password": "$2b$12$placeholderhashforbob", # Replace with actual hash
        "disabled": False,
    }
}

# --------------------------------------------------------------------------
# Password Hashing Setup (using passlib)
# --------------------------------------------------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """ Checks if a plain password matches a stored hash """
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """ Generates a bcrypt hash for a given password """
    return pwd_context.hash(password)

# --------------------------------------------------------------------------
# User Utility Functions (interacting with fake DB)
# --------------------------------------------------------------------------
def get_user(username: str) -> UserInDB | None:
    """ Looks up a user in the fake database """
    if username in fake_users_db:
        user_dict = fake_users_db[username]
        return UserInDB(**user_dict)
    return None

def authenticate_user(username: str, password: str) -> UserInDB | None:
    """ Authenticates a user: checks username exists and password is correct """
    user = get_user(username)
    if not user:
        # User not found
        return None
    if not verify_password(password, user.hashed_password):
        # Incorrect password
        return None
    # Authentication successful
    return user

# --------------------------------------------------------------------------
# JWT Token Creation
# --------------------------------------------------------------------------
def create_access_token(data: dict, expires_delta: timedelta | None = None) -> str:
    """ Creates a JWT access token """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        # Default expiry if none provided
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire}) # Add the expiration time claim
    # Use PyJWT's encode function
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --------------------------------------------------------------------------
# Dependency for Getting Current User (Token Verification)
# --------------------------------------------------------------------------
# This tells FastAPI how to get the token (from Authorization: Bearer <token> header)
# tokenUrl="token" points to our login endpoint path below
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
    """ Decodes token, validates it, and returns the user """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"}, # Standard header for 401
    )
    try:
        # Decode the token using PyJWT
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        # 'sub' is the standard claim for the subject (usually username)
        username: str | None = payload.get("sub")
        if username is None:
            raise credentials_exception # Username not found in token payload
        # Store username in our TokenData model (optional, good practice)
        token_data = TokenData(username=username)
    except InvalidTokenError: # Catch errors from jwt.decode (e.g., bad signature, expired)
        raise credentials_exception

    # Get the user from our fake DB based on the username from the token
    user = get_user(username=token_data.username)
    if user is None:
        # User may have been deleted after token was issued
        raise credentials_exception
    # Return the full user object (including hashed password, be careful!)
    return user

async def get_current_active_user(
    current_user: Annotated[UserInDB, Depends(get_current_user)]
) -> UserInDB:
    """ Gets the current user and checks if they are active """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    # Return the validated, active user
    # We return UserInDB here, but the endpoint response_model might restrict fields
    return current_user

# --------------------------------------------------------------------------
# FastAPI Application Instance
# --------------------------------------------------------------------------
app = FastAPI()

# --------------------------------------------------------------------------
# API Endpoints
# --------------------------------------------------------------------------

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()]
):
    """
    Login endpoint. Takes username and password from form data,
    returns an access token if credentials are valid.
    """
    # form_data contains 'username' and 'password' fields
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    # Create the access token
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        # Data to put inside the token, 'sub' is standard for username
        data={"sub": user.username},
        expires_delta=access_token_expires
    )
    # Return the token in the format specified by the Token model
    return {"access_token": access_token, "token_type": "bearer"}


@app.get("/users/me", response_model=User)
async def read_users_me(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)]
):
    """
    Protected endpoint. Returns the current authenticated user's details.
    It automatically uses get_current_active_user dependency.
    The response_model=User ensures the hashed_password is NOT sent back.
    """
    # If code execution reaches here, the user is authenticated and active.
    # current_user is the UserInDB object returned by the dependency.
    return current_user

# Example of another protected endpoint:
@app.get("/users/me/items")
async def read_own_items(
    current_user: Annotated[UserInDB, Depends(get_current_active_user)]
):
    """ Another example protected route """
    # You can use current_user.username or other details here
    return [{"item_id": "Foo", "owner": current_user.username}]

# --------------------------------------------------------------------------
# Helper for generating password hashes (Run manually if needed)
# --------------------------------------------------------------------------
# Uncomment the lines below and run `python main.py` in your terminal
# to generate a hash for a new password. Then copy the output hash
# into the fake_users_db above. Remember to comment them out again after use!

# if __name__ == "__main__":
#     print("Password Hasher Utility")
#     password_to_hash = input("Enter password to hash: ")
#     hashed_pw = get_password_hash(password_to_hash)
#     print(f"Hashed password for '{password_to_hash}':")
#     print(hashed_pw)

# To run the app: uvicorn main:app --reload