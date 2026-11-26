from __future__ import annotations

import os

import uvicorn
from dotenv import load_dotenv

load_dotenv()

from app.main import app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.environ.get("HOST", "127.0.0.1"),
        port=int(os.environ.get("API_PORT", os.environ.get("PORT", "8000"))),
    )
