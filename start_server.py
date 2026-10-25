import os
import sys

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
sys.path.insert(0, BASE_DIR)

import uvicorn
from backend.app import app

if __name__ == "__main__":
    print(f"Starting Forensic Server on http://127.0.0.1:8000 (Serving API & Frontend)")
    uvicorn.run(app, host="127.0.0.1", port=8000, log_level="info")
