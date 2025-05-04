from pydantic import BaseModel

class Token(BaseModel):
  """ Response model for issuing a token """
  access_token: str
  token_type: str

class TokenData(BaseModel):
  """ Data hidden inside the JWT token """
  username: str | None = None