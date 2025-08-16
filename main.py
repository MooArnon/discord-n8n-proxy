import os
import json
import requests
from fastapi import FastAPI, Request, Header, HTTPException
from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError

DISCORD_PUBLIC_KEY = os.getenv("DISCORD_PUBLIC_KEY")  # from Developer Portal
N8N_WEBHOOK_URL = os.getenv("N8N_WEBHOOK_URL")        # your n8n webhook

app = FastAPI()
verify_key = VerifyKey(bytes.fromhex(DISCORD_PUBLIC_KEY))

@app.post("/interactions")
async def interactions(
    request: Request,
    x_signature_ed25519: str = Header(...),
    x_signature_timestamp: str = Header(...)
):
    body = await request.body()

    # --- verify Discord signature ---
    try:
        verify_key.verify(
            x_signature_timestamp.encode() + body,
            bytes.fromhex(x_signature_ed25519)
        )
    except BadSignatureError:
        raise HTTPException(status_code=401, detail="Invalid signature")

    data = json.loads(body)

    # --- PING (Discord handshake) ---
    if data["type"] == 1:
        return {"type": 1}

    # --- Slash command invoked ---
    if data["type"] == 2:
        # forward raw payload to n8n
        requests.post(N8N_WEBHOOK_URL, json=data)

        # immediate response to Discord
        return {
            "type": 4,
            "data": {"content": "✅ Command received, processing in n8n..."}
        }
