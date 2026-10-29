"""Core configuration for OSS Dependency Intelligence."""
from pathlib import Path
from pydantic import BaseModel
import os

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

class Settings(BaseModel):
    PROJECT_NAME: str = "OSS Dependency Intelligence"
    TAGLINE: str = "Understand Your Dependencies. Detect Risks. Ship with Confidence."
    VERSION: str = "1.0.0"
    API_V1_PREFIX: str = "/api/v1"
    
    DB_PATH: Path = DATA_DIR / "ossdi.sqlite3"
    
    # OSV Vulnerability Provider
    OSV_API_URL: str = os.getenv("OSV_API_URL", "https://api.osv.dev/v1/querybatch")
    OSV_TIMEOUT_SECONDS: float = float(os.getenv("OSV_TIMEOUT_SECONDS", "10.0"))
    CACHE_EXPIRATION_HOURS: int = int(os.getenv("CACHE_EXPIRATION_HOURS", "24"))
    
    # Security limits
    MAX_FILE_SIZE_BYTES: int = 15 * 1024 * 1024  # 15MB
    MAX_UNCOMPRESSED_BYTES: int = 50 * 1024 * 1024  # 50MB
    MAX_ARCHIVE_FILES: int = 1000
    
    # Static UI directory if built
    WEB_DIST_DIR: Path = BASE_DIR.parent / "apps" / "web" / "dist"

settings = Settings()
