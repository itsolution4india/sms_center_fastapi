from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Optional
import secrets

app = FastAPI()

# --- Logging Setup ---
os.makedirs("logs", exist_ok=True)
log_path = "logs/sms_api.log"

log_handler = RotatingFileHandler(
    log_path,
    maxBytes=5 * 1024 * 1024,
    backupCount=5
)
log_handler.setLevel(logging.INFO)
log_handler.setFormatter(logging.Formatter(
    "%(asctime)s - %(levelname)s - %(name)s - %(message)s"
))

logger = logging.getLogger("sms_api_logger")
logger.setLevel(logging.INFO)
logger.addHandler(log_handler)
logger.propagate = False

# --- Basic Auth Setup ---
security = HTTPBasic()

USERNAME = "admin"
PASSWORD = "supersecret"

def authenticate(credentials: HTTPBasicCredentials = Depends(security)):
    correct_username = secrets.compare_digest(credentials.username, USERNAME)
    correct_password = secrets.compare_digest(credentials.password, PASSWORD)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

# --- Webhook ---
@app.post("/webhook")
async def receive_webhook(request: Request):
    try:
        data = await request.json()
        client_ip = request.client.host
        logger.info(f"Received data from {client_ip}: {data}")
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Error while processing request: {e}")
        return {"status": "error", "message": str(e)}

# --- Logs API ---
@app.get("/logs")
def get_logs(
    lines: Optional[int] = 100,
    user: str = Depends(authenticate)
):
    if not os.path.exists(log_path):
        raise HTTPException(status_code=404, detail="Log file not found")

    try:
        with open(log_path, "r") as f:
            all_lines = f.readlines()
            return {"log_lines": all_lines[-lines:]}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read logs: {e}")
