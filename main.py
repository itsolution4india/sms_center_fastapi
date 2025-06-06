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
import asyncio

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


def extract_otp(text_message: str) -> str:
    match = re.search(r"\b\d{4,6}\b", text_message)
    if match:
        return match.group()
    
    if '\x00' in text_message:
        cleaned = ''.join(c for c in text_message if c != '\x00')
        match = re.search(r"\b\d{4,6}\b", cleaned)
        if match:
            return match.group()
    
    try:
        if '\\x' in repr(text_message):
            decoded = text_message.encode().decode('unicode_escape')
            match = re.search(r"\b\d{4,6}\b", decoded)
            if match:
                return match.group()
    except Exception:
        pass
    
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

# async def save_to_database(data):
#     pool = await aiomysql.create_pool(
#         host='localhost',
#         port=3306,
#         user='prashanth@itsolution4india.com',
#         password='Solution@97',
#         db='smsc_table',
#         autocommit=True
#     )

#     async with pool.acquire() as conn:
#         async with conn.cursor() as cur:
#             await cur.execute("""
#                 INSERT INTO smsc_responses (username, source_addr, destination_addr, short_message, wamid, message_id)
#                 VALUES (%s, %s, %s, %s, %s, %s)
#             """, (
#                 data.get("username"),
#                 data.get("source_addr"),
#                 data.get("destination_addr"),
#                 data.get("short_message"),
#                 None,
#                 data.get("message_id")
#             ))
#     pool.close()
#     await pool.wait_closed()

async def save_to_database(message_id: str, username: str, source_addr: str, contact: str, short_message: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_db',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            # Insert a new record if wamid doesn't exist
            await cur.execute("""
                INSERT INTO smsc_responses (
                    message_id,
                    username,
                    source_addr,
                    destination_addr,
                    short_message
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (message_id, username, source_addr, contact, short_message))

    pool.close()
    await pool.wait_closed()

async def update_wamid_in_database(message_id: str, wamid: str, username: str, source_addr: str, contact: str, short_message: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_db',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            # Check if the wamid already exists
            await cur.execute("SELECT id FROM smsc_responses WHERE wamid = %s", (wamid,))
            result = await cur.fetchone()

            if result:
                # Update the record if wamid exists
                await cur.execute("""
                    UPDATE smsc_responses
                    SET message_id = %s,
                        username = %s,
                        source_addr = %s,
                        destination_addr = %s,
                        short_message = %s
                    WHERE wamid = %s
                """, (message_id, username, source_addr, contact, short_message, wamid))
            else:
                # Insert a new record if wamid doesn't exist
                await cur.execute("""
                    INSERT INTO smsc_responses (
                        wamid,
                        message_id,
                        username,
                        source_addr,
                        destination_addr,
                        short_message
                    ) VALUES (%s, %s, %s, %s, %s, %s)
                """, (wamid, message_id, username, source_addr, contact, short_message))

    pool.close()
    await pool.wait_closed()
    
async def deduct_coin_for_user(username: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_db',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor() as cur:
            await cur.execute("""
                UPDATE whatsapp_services
                SET balance = balance - 1
                WHERE username = %s AND balance > 0
            """, (username,))
    pool.close()
    await pool.wait_closed()
    
async def get_user_config(username: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_db',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute("SELECT * FROM whatsapp_services WHERE username=%s", (username,))
            row = await cur.fetchone()
            if row:
                return row
            else:
                raise ValueError(f"User {username} not found")

async def get_whatsapp_config(username: str):
    pool = await aiomysql.create_pool(
        host='localhost',
        port=3306,
        user='prashanth@itsolution4india.com',
        password='Solution@97',
        db='smsc_db',
        autocommit=True
    )

    async with pool.acquire() as conn:
        async with conn.cursor(aiomysql.DictCursor) as cur:
            await cur.execute("""
                SELECT phone_id, token, template_name 
                FROM whatsapp_numbers 
                WHERE username = %s AND number_status = 'active'
                ORDER BY created_at DESC LIMIT 1
            """, (username,))
            row = await cur.fetchone()
            if row:
                return row
            else:
                raise ValueError(f"No active WhatsApp config found for user {username}")
    
async def process_messages_in_chunks(messages, tps, send_func):
    for i in range(0, len(messages), tps):
        chunk = messages[i:i + tps]
        await asyncio.gather(*(send_func(msg) for msg in chunk))
        await asyncio.sleep(1)  # Wait 1 second between chunks


async def send_otp_message(session: aiohttp.ClientSession, token: str, phone_number_id: str, template_name: str, language: str, contact: str, message_id: str, username: str, short_message: str, source_addr: str, variables: ty.Optional[ty.List[str]] = None) -> None:
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
                    await update_wamid_in_database(message_id, wamid, username, source_addr, contact, short_message)
                    await deduct_coin_for_user(username)
                else:
                    await save_to_database(message_id, username, source_addr, contact, short_message)

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

@app.post("/webhook")
async def receive_webhook(request: Request):
    data = await request.json()
    client_ip = request.client.host
    logger.info(f"Received data from {client_ip}: {data}")

    try:
        # await save_to_database(data)
        username = data.get("username")
        destination_addr = data.get("destination_addr")
        text_message = data.get("short_message")
        message_id = data.get("message_id")
        
        source_addr = data.get("source_addr"),

        # Get config from DB
        user_config = await get_user_config(username)
        tps = user_config["tps"]
        language = user_config["language"]

        whatsapp_config = await get_whatsapp_config(username)
        token = whatsapp_config["token"]
        phone_number_id = str(whatsapp_config["phone_id"])
        template_name = whatsapp_config["template_name"]

        # Prepare message
        otp = extract_otp(str(text_message))
        variables = [otp]
        message_obj = {
            "token": token,
            "phone_number_id": phone_number_id,
            "template_name": template_name,
            "language": language,
            "contact": destination_addr,
            "message_id": message_id,
            "username": username,
            "variables": variables,
            "short_message": text_message,
            "source_addr": source_addr
        }

        async def send_func(msg):
            async with aiohttp.ClientSession() as session:
                await send_otp_message(
                    session=session,
                    token=msg["token"],
                    phone_number_id=msg["phone_number_id"],
                    template_name=msg["template_name"],
                    language=msg["language"],
                    contact=msg["contact"],
                    message_id=msg["message_id"],
                    username=msg["username"],
                    short_message=msg['short_message'],
                    source_addr=msg['source_addr'],
                    variables=msg["variables"]
                )

        # Send the message (1 per webhook, but prepared for batch)
        await process_messages_in_chunks([message_obj], tps, send_func)

        return {"status": "received"}

    except Exception as e:
        logger.error(f"Error while processing request: {e}")
        return {"status": "error", "message": str(e)}

@app.get("/")
def root():
    logger.info("Root endpoint accessed")
    return {"message": "Send SMS API Successful"}