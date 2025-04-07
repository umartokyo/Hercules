from typing import Annotated, List
from fastapi import APIRouter, Depends

from app.api import deps
from app.schemas.user import User, UserInDB

router = APIRouter()

@router.get("/me", response_model=User)
async def read_users_me(current_user: Annotated[UserInDB, Depends(deps.get_current_active_user)]):
  """ Get current logged-in user's details """
  return current_user

@router.get("/me/items")
async def read_own_items(current_user: Annotated[UserInDB, Depends(deps.get_current_active_user)]):
  """ Example protected route requiring authenticated user """
  return [{"item_id": "Foo", "owner": current_user.username}]