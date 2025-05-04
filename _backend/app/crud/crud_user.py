from app.core import security
from app.schemas.user import UserInDB

fake_users_db = {
    "johndoe": {
        "username": "johndoe",
        "full_name": "John Doe",
        "email": "johndoe@example.com",
        # Hash for 'secure'
        "hashed_password": "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxn96p36WQoeG6Lruj3vjPGga31lW", # Hash for 'secret'
        "disabled": False,
    },
     "coach_bob": {
        "username": "coach_bob",
        "full_name": "Coach Bob",
        "email": "bob@example.com",
        # Use the hash generated earlier for 'password123'
        "hashed_password": "$2b$12$.DML6PX8sGS7vafntquwPejzA/yd5Gi4SMG0.gomBjyFnHcyp8vZu", # Hash for 'password123'
        "disabled": False,
    }
}

def get_user(username: str) -> UserInDB | None:
  """ Looks up a user in the fake database """
  if username in fake_users_db:
    user_dict = fake_users_db[username]
    return UserInDB(**user_dict)
  return None

def authentificate_user(username: str, password: str) -> UserInDB | None:
  """ Authenticates a user using fake DB """
  user = get_user(username)
  if not user:
    return None
  if not security.verify_password(password, user.hashed_password):
    return None
  return user