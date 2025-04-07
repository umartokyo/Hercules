import os
from pydantic_settings import BaseSettings, SettingsConfigDict
from dotenv import load_dotenv

load_dotenv()

class Settings(BaseSettings):
  PROJECT_NAME: str = "Hercules"
  APP_V1_STR: str = "/api/v1"

  SECRET_KEY: str
  ALGORITHM: str = "HS256"
  ACCESS_TOKEN_EXPIRE_MINUTES: int = 30

  model_config = SettingsConfigDict(
    env_file=".env",
    env_file_encoding='utf-8',
    extra='ignore',
  )

settings = Settings()