from fastapi import FastAPI
import requests, hashlib, hmac, datetime
from pydantic import BaseModel

app = FastAPI()

class SPAPIRequest(BaseModel):
    access_token: str
    aws_access_key: str
    aws_secret_key: str
    region: str
    host: str
    endpoint: str
    method: str = "GET"

@app.post("/spapi-request")
def call_spapi(req: SPAPIRequest):
    service = "execute-api"
    t = datetime.datetime.utcnow()
    amz_date = t.strftime('%Y%m%dT%H%M%SZ')
    datestamp = t.strftime('%Y%m%d')
    canonical_headers = f"host:{req.host}\nx-amz-access-token:{req.access_token}\n"
    signed_headers = "host;x-amz-access-token"
    payload_hash = hashlib.sha256(("").encode("utf-8")).hexdigest()
    canonical_request = "\n".join([
        req.method,
        req.endpoint,
        "",
        canonical_headers,
        signed_headers,
        payload_hash
    ])
    credential_scope = f"{datestamp}/{req.region}/{service}/aws4_request"
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256",
        amz_date,
        credential_scope,
        hashlib.sha256(canonical_request.encode("utf-8")).hexdigest()
    ])
    def sign(key, msg): return hmac.new(key, msg.encode('utf-8'), hashlib.sha256).digest()
    kDate = sign(('AWS4' + req.aws_secret_key).encode('utf-8'), datestamp)
    kRegion = sign(kDate, req.region)
    kService = sign(kRegion, service)
    kSigning = sign(kService, 'aws4_request')
    signature = hmac.new(kSigning, string_to_sign.encode('utf-8'), hashlib.sha256).hexdigest()
    authorization_header = (
        f"AWS4-HMAC-SHA256 Credential={req.aws_access_key}/{credential_scope}, "
        f"SignedHeaders={signed_headers}, Signature={signature}"
    )
    headers = {
        "Authorization": authorization_header,
        "x-amz-date": amz_date,
        "x-amz-access-token": req.access_token,
        "host": req.host
    }
    url = f"https://{req.host}{req.endpoint}"
    response = requests.request(req.method, url, headers=headers)
    return {
        "status_code": response.status_code,
        "response": response.json() if response.content else {},
        "url": url
    }
