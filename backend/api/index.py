"""Vercel serverless entrypoint for the FastAPI backend."""

import os
import sys
from pathlib import Path


BACKEND_ROOT = Path(__file__).resolve().parent.parent

if str(BACKEND_ROOT) not in sys.path:
    sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("SKIP_STARTUP_INDEXES", "true")

from main import app
