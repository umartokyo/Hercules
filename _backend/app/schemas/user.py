from pydantic import BaseModel

class UserBase(BaseModel):
  """ Base user model with common fields """
  username: str
  email: str | None = None
  ful_name: str | None = None
  disabled: bool | None = False

class User(UserBase):
  """ Model for returning user info (excluding sensitive data) """
  pass

class UserInDBBase(UserBase):
  """ Base model for user data stored in DB (includes hashed password) """
  hashed_password: str

class UserInDB(UserInDBBase):
  """ Final model representing user object fetched from DB """
  pass