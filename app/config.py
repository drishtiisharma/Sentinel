from pydantic_settings import BaseSettings
from typing import List
import os

class Settings(BaseSettings):
    PROJECT_NAME: str = "AIOps Sentinel"
    VERSION: str = "2.0.0"
    
    # Database
    DATABASE_URL: str = "sqlite:///./aiops.db"
    
    # Gemini API
    GEMINI_API_KEY: str = ""
    GEMINI_ENABLED: bool = False
    
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
    
    # Serving
    SERVE_STATIC: bool = True
    
    class Config:
        env_file = ".env"
        case_sensitive = False

settings = Settings()