from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "SENTINEL AIOps API"
    VERSION: str = "2.0.0"
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./aiops.db")
    
    # Gemini API
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    GEMINI_ENABLED: bool = bool(os.getenv("GEMINI_API_KEY", ""))
    
    # ML Settings
    SIMILARITY_THRESHOLD: float = 0.75
    CLUSTERING_EPS: float = 0.5
    CLUSTERING_MIN_SAMPLES: int = 2
    NOISE_REDUCTION_ENABLED: bool = True
    
    # Alert Generation
    REALISTIC_NOISE: bool = True
    PATTERN_REPEAT_PROBABILITY: float = 0.3
    
    # Security
    CORS_ORIGINS: List[str] = ["*"]
    
    class Config:
        env_file = ".env"

settings = Settings()