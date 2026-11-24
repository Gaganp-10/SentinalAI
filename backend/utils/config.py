import os
import json
import ipaddress
from typing import List, Optional, Union
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import field_validator, model_validator

# Resolve the .env path relative to this file so it works regardless of CWD
_ENV_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".env")

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = "Security Vulnerability Detector and Fixer"
    API_V1_STR: str = "/api/v1"
    SECRET_KEY: str = "SUPER_SECRET_KEY_CHANGE_ME_IN_PRODUCTION_1234567890"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 8  # 8 days
    GOOGLE_CLIENT_ID: str = "1020864929554-v9mb9l065pedkr9ah01a1n3jsggfbc5c.apps.googleusercontent.com"

    # Environment mode — guards the console email backend
    # Values: "development" | "production" | "staging"
    ENV: str = "development"

    # Password reset
    FRONTEND_URL: str = "http://localhost:3000"
    PASSWORD_RESET_EXPIRE_MINUTES: int = 30

    # Email backend: "console" (dev only) | "smtp"
    EMAIL_BACKEND: str = "console"
    SMTP_HOST: str = ""
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM: str = ""
    SMTP_USE_TLS: bool = True  # STARTTLS
    
    # Postgres configuration
    POSTGRES_SERVER: str = "db"
    POSTGRES_USER: str = "postgres"
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = "security_scanner"
    DATABASE_URL: Optional[str] = None

    # AI Provider configuration
    AI_PROVIDER: str = "template"   # "groq" | "ollama" | "openai" | "template"
    GROQ_API_KEY: str = ""
    GROQ_MODEL: str = "llama-3.3-70b-versatile"
    OLLAMA_BASE_URL: str = "http://localhost:11434/v1"
    OLLAMA_MODEL: str = "qwen2.5-coder:7b"
    OPENAI_API_KEY: Optional[str] = None
    OPENAI_MODEL: str = "gpt-4o-mini"

    # Uploads configuration
    UPLOAD_DIR: str = "uploads"
    MAX_UPLOAD_SIZE_MB: int = 2               # 2 MB per source file
    MAX_ZIP_UPLOAD_SIZE_MB: int = 50          # 50 MB zip upload cap
    MAX_MANIFEST_UPLOAD_SIZE_MB: int = 10     # 10 MB per manifest
    MAX_ZIP_FILES: int = 5000                 # 5000 kept files limit
    MAX_ZIP_RATIO: float = 100.0              # 100 max compression ratio
    MAX_UNCOMPRESSED_SIZE_MB: int = 500       # 500 MB total uncompressed
    ALLOWED_EXTENSIONS: List[str] = ["py", "js", "jsx", "ts", "tsx", "java", "c", "cpp", "h", "php", "zip"]

    # OSV.dev SCA configuration
    OSV_API_BASE_URL: str = "https://api.osv.dev"

    # CORS configuration
    ALLOWED_ORIGINS: Union[List[str], str] = ["*"]

    # Abuse controls & Production Access
    ALLOW_SIGNUP: bool = True
    GOOGLE_AUTH_ALLOWLIST: str = ""
    MAX_PROJECTS_PER_USER: Optional[int] = None
    MAX_DAILY_UPLOADS_PER_USER: Optional[int] = None
    MAX_DAILY_UPLOAD_MB_PER_USER: Optional[int] = None
    MAX_USER_STORAGE_MB: Optional[int] = None

    # Auth Rate Limiting
    AUTH_RATE_LIMIT_LOGIN_PER_IP: int = 10
    AUTH_RATE_LIMIT_LOGIN_PER_ACCOUNT: int = 10
    AUTH_RATE_LIMIT_SIGNUP_PER_IP: int = 10
    AUTH_RATE_LIMIT_SIGNUP_PER_ACCOUNT: int = 5

    # Trusted Proxies (CIDR list or comma-separated string)
    # Default for local development/standalone is loopback only.
    # Production overrides this via environment variable (e.g. Caddy container static IP 172.28.0.2/32).
    TRUSTED_PROXIES: Union[List[str], str] = ["127.0.0.1/32", "::1/128"]

    # Scan Controls
    MAX_CONCURRENT_SCANS: int = 2
    SCAN_TIMEOUT_SECONDS: int = 300
    SCANNER_TIMEOUT_SECONDS: int = 300

    # AI Controls
    MAX_AI_EXPLANATIONS_PER_SCAN: int = 10
    MAX_DAILY_COPILOT_CHATS_PER_USER: int = 50

    @model_validator(mode="after")
    def validate_production_security(self) -> "Settings":
        env_mode = (self.ENV or "development").strip().lower()
        if env_mode != "development":
            insecure_keys = {
                "SUPER_SECRET_KEY_CHANGE_ME_IN_PRODUCTION_1234567890",
                "dev-secret-key-change-later-for-production-min-32-chars",
                "a_very_secure_random_key_value_min_32_characters",
                "dev-secret-key-change-later",
                "change-this-in-production",
            }
            if not self.SECRET_KEY or self.SECRET_KEY in insecure_keys or len(self.SECRET_KEY) < 32:
                raise ValueError(
                    f"Production/staging mode (ENV='{self.ENV}') requires a secure SECRET_KEY "
                    "that is not a default placeholder and has at least 32 characters."
                )
            if not self.POSTGRES_PASSWORD or self.POSTGRES_PASSWORD.strip() == "" or self.POSTGRES_PASSWORD == "postgres":
                raise ValueError(
                    f"Production/staging mode (ENV='{self.ENV}') requires a non-default POSTGRES_PASSWORD "
                    "(cannot be empty or 'postgres')."
                )
            if self.DATABASE_URL and ":postgres@" in self.DATABASE_URL:
                raise ValueError(
                    f"Production/staging mode (ENV='{self.ENV}') DATABASE_URL contains default password 'postgres'."
                )
        return self

    @field_validator("TRUSTED_PROXIES", mode="before")
    @classmethod
    def assemble_trusted_proxies(cls, v: str | List[str]) -> List[str]:
        items: List[str] = []
        if isinstance(v, list):
            items = [str(p).strip() for p in v if str(p).strip()]
        elif isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                try:
                    parsed = json.loads(v)
                    if isinstance(parsed, list):
                        items = [str(p).strip() for p in parsed if str(p).strip()]
                    else:
                        items = [p.strip() for p in v.split(",") if p.strip()]
                except json.JSONDecodeError:
                    items = [p.strip() for p in v.split(",") if p.strip()]
            else:
                items = [p.strip() for p in v.split(",") if p.strip()]
        elif v is not None:
            items = [str(v).strip()]

        for item in items:
            try:
                if "/" in item:
                    ipaddress.ip_network(item, strict=False)
                else:
                    ipaddress.ip_network(f"{item}/32" if ":" not in item else f"{item}/128", strict=False)
            except ValueError as e:
                raise ValueError(f"Invalid trusted proxy CIDR or IP configured in TRUSTED_PROXIES: {item!r}") from e

        return items

    @field_validator("ALLOWED_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: str | List[str]) -> List[str]:
        """
        Handles ALLOWED_ORIGINS from .env in multiple formats:
        - Already a list: pass through
        - JSON array string: '["http://localhost:3000","http://localhost:5173"]'
        - Comma-separated string: 'http://localhost:3000,http://localhost:5173'
        """
        if isinstance(v, list):
            return v
        if isinstance(v, str):
            v = v.strip()
            if v.startswith("["):
                try:
                    return json.loads(v)
                except json.JSONDecodeError:
                    pass
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v

    @property
    def sqlalchemy_database_uri(self) -> str:
        if self.DATABASE_URL:
            # Handle standard postgresql:// vs postgres:// replacement for modern SQLAlchemy
            url = self.DATABASE_URL
            if url.startswith("postgres://"):
                url = url.replace("postgres://", "postgresql://", 1)
            return url
        return f"postgresql://{self.POSTGRES_USER}:{self.POSTGRES_PASSWORD}@{self.POSTGRES_SERVER}/{self.POSTGRES_DB}"

settings = Settings()
