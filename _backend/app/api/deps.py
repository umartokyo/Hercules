from typing import Annotated
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
import jwt
from jwt.exceptions import InvalidTokenError

from app.core.config import settings
from app.core import security
from app.crud import crud_user
from app.schemas.token import TokenData
from app.schemas.user import UserInDB

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")

# Exception to be raised on authentification error
credentials_exception = HTTPException(
  status_code=status.HTTP_401_UNAUTHORIZED,
  detail="Could not validate credentials",
  headers={"WWW-Authenticate": "Bearer"},
)

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)]) -> UserInDB:
  """ Dependency to get the current user from JWT token """
  try:
    payload = jwt.decode(
      token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM]
    )
    username: str | None = payload.get("sub")
    if username is None:
      raise credentials_exception
    token_date = TokenData(username=username)
  except InvalidTokenError:
    raise credentials_exception

  user = crud_user.get_user(username=token_date.username)
  if user is None:
    raise credentials_exception
  return user

async def get_current_active_user(current_user: Annotated[UserInDB, Depends(get_current_user)]) -> UserInDB:
  """ Dependency to get the current active user """
  if current_user.disabled:
    raise HTTPException(status_code=400, detail="Inactive user")
  return current_user