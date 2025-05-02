from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
import logging
from logging.handlers import RotatingFileHandler
import os
from typing import Optional
import secrets
import aiohttp
import typing as ty
import json
import re
import aiomysql

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

# WhatsApp configuration
WHATSAPP_TOKEN = "EAAGZBdt7VWLcBO8nr7i8nChTcNXzWF9aNMjPYVjjKU7BbNfIJGETpZAJY3A2y9vLxzo4xZCace1xKiqG7jS7772Hpak96BPl360cG8Dzt83ujr8BSwGyUbNRS2mIjwZBfUwhNFKXtpFZC2QJ9Lh6OcKLRuoNJ1sAXGk2LZBkNu9BN7JSpBbTnU2vR6neoYv4FFUwZDZD"
PHONE_NUMBER_ID = "498352686693631"
TEMPLATE_NAME = "testauthtemp875"
LANGUAGE = "en"

def extract_otp(text_message: str) -> str:
    match = re.search(r"\b\d{6}\b", text_message)
    if match:
        return match.group()
    return None

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

async def save_to_database(data):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_table',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                INSERT INTO smsc_responses (system_id, bindtype, username, session_id, source_addr, destination_addr, short_message, wamid, message_id)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                data.get("username"),
                data.get("source_addr"),
                data.get("destination_addr"),
                data.get("short_message"),
                None,
                data.get("message_id")
            ))
    pool.close()
    await pool.wait_closed()

async def update_wamid_in_database(message_id: str, wamid: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_table',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                UPDATE smsc_responses
                SET wamid = %s
                WHERE message_id = %s
            """, (wamid, message_id))
    pool.close()
    await pool.wait_closed()

# --- Webhook ---
@app.post("/webhook")
async def receive_webhook(request: Request):
    try:
        data = await request.json()
        client_ip = request.client.host
        logger.info(f"Received data from {client_ip}: {data}")
        
        await save_to_database(data)

        destination_addr = data.get("destination_addr")
        text_message = data.get("short_message")
        message_id = data.get("message_id")
        otp = extract_otp(text_message)
        variables = [f"{otp}"]
        logger.info(f"Triggering WhatsApp OTP to {destination_addr} with variables {variables}")

        async with aiohttp.ClientSession() as session:
            result = await send_otp_message(
                session=session,
                token=WHATSAPP_TOKEN,
                phone_number_id=PHONE_NUMBER_ID,
                template_name=TEMPLATE_NAME,
                language=LANGUAGE,
                contact=destination_addr,
                message_id=message_id,
                variables=variables
            )
            logger.info(f"WhatsApp API response: {result}")

        return {"status": "received"}

    except Exception as e:
        logger.error(f"Error while processing request: {e}")
        return {"status": "error", "message": str(e)}
    
async def send_otp_message(session: aiohttp.ClientSession, token: str, phone_number_id: str, template_name: str, language: str, contact: str, message_id: str, variables: ty.Optional[ty.List[str]] = None) -> None:
    url = f"https://graph.facebook.com/v20.0/{phone_number_id}/messages"
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json"
    }

    header_component = {
        "type": "header",
        "parameters": []
    }

    body_component = {
        "type": "body",
        "parameters": []
    }

    button_component = {
        "type": "button",
        "sub_type": "url",
        "index": "0",
        "parameters": []
    }
    
    if variables:
        body_component["parameters"] = [
            {
                "type": "text",
                "text": variable
            } for variable in variables
        ]

    button_component["parameters"].append({
        "type": "text",
        "text": variables[0]
    })

    payload = {
        "messaging_product": "whatsapp",
        "to": contact,
        "type": "template",
        "template": {
            "name": template_name,
            "language": {"code": language},
            "components": [
                header_component,
                body_component,
                button_component
            ]
        },
        "context": {
            "message_id": f"template_{template_name}_{json.dumps({'template_name': template_name, 'language': language})}"
        }
    }

    try:
        async with session.post(url, json=payload, headers=headers) as response:
            response_text = await response.text()
            if response.status == 200:
                logger.info(f"WhatsApp API success response: {response_text}")

                # Parse the wamid
                response_json = await response.json()
                wamid = response_json.get("messages", [{}])[0].get("id")

                # Update wamid in database
                if wamid:
                    await update_wamid_in_database(message_id, wamid)

                return {
                    "status": "success",
                    "contact": contact,
                    "message_id": f"template_{template_name}",
                    "response": response_text
                }
            else:
                logger.error(f"Failed to send message to {contact}. Status: {response.status}, Error: {response_text}")
                return {
                    "status": "failed",
                    "contact": contact,
                    "error_code": response.status,
                    "error_message": response_text
                }
    except aiohttp.ClientError as e:
        logger.error(f"Error sending message to {contact}: {e}")
        return {
            "status": "failed",
            "contact": contact,
            "error_code": "client_error",
            "error_message": str(e)
        }

@app.get("/")
def root():
    logger.info("Root endpoint accessed")
    return {"message": "Send SMS API Successful"}