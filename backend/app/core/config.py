from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import Optional


class Settings(BaseSettings):
    # App
    APP_NAME: str = "Conversational SIEM Assistant"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    API_PREFIX: str = "/api"

    # Security / JWT
    SECRET_KEY: str = "change-me-in-production-use-a-long-random-string"
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Database (defaults to zero-dependency SQLite for local dev, PostgreSQL supported via env var)
    DATABASE_URL: str = "sqlite+aiosqlite:///./siem.db"

    # Elasticsearch
    ELASTICSEARCH_URL: str = "http://localhost:9200"
    ELASTICSEARCH_INDEX: str = "siem-logs"
    ELASTICSEARCH_USERNAME: Optional[str] = None
    ELASTICSEARCH_PASSWORD: Optional[str] = None

    # LLM — configurable provider
    LLM_PROVIDER: str = "gemini"          # gemini | openai | anthropic | mock
    GEMINI_API_KEY: Optional[str] = None
    OPENAI_API_KEY: Optional[str] = None
    ANTHROPIC_API_KEY: Optional[str] = None
    LLM_MODEL: str = "gemini-1.5-flash"  # default model

    # SIEM mode
    SIEM_MODE: str = "mock"               # mock | elasticsearch | wazuh

    # ChromaDB (RAG)
    CHROMA_PERSIST_DIR: str = "./data/chroma_db"
    MITRE_COLLECTION: str = "mitre_attack"

    # CORS
    CORS_ORIGINS: list[str] = ["http://localhost:5173", "http://localhost:3000"]

    # Rate limiting
    RATE_LIMIT_CHAT: int = 30            # requests per minute
    RATE_LIMIT_INVESTIGATE: int = 20

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")


settings = Settings()

