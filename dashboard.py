import os, uuid, base64
from typing import Dict, Any, List, Optional

import asyncpg
from fastapi import FastAPI, Request, Depends, HTTPException, status, Form
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from contextlib import asynccontextmanager
from fastapi.templating import Jinja2Templates
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# -----------------------------
# Basic auth
# -----------------------------
security = HTTPBasic()
ADMIN_USER = "admin"
ADMIN_PASS = "Admin#1234"

def require_admin(creds: HTTPBasicCredentials = Depends(security)):
    if not (creds.username == ADMIN_USER and creds.password == ADMIN_PASS):
        # browser will show login prompt
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, headers={"WWW-Authenticate": "Basic"})
    return True

# -----------------------------
# Config from env
# -----------------------------
DB_USER = os.getenv("DATABASE_USER", "postgres")
DB_PASS = os.getenv("DATABASE_PASSWORD", "")
DB_HOST = os.getenv("DATABASE_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DATABASE_PORT", "5432"))
DB_NAME = os.getenv("DATABASE_NAME", "veremark_connector")
AES_KEY = os.getenv("AES_KEY", "")   # hex string (16/24/32 bytes)
AES_IV  = os.getenv("AES_IV", "")    # hex string (12 bytes)

POOL: asyncpg.Pool | None = None

# Columns that must be encrypted (exact per your requirement)
ENCRYPTED_COLUMNS = {
    "platform": ["connector_api_key"],
    "tenant": [
        "platform_api_username",
        "platform_api_password",
        "connector_platform_username",
        "connector_platform_password",
        "veremark_api_token",
        "connector_veremark_username",
        "connector_veremark_password",
        "connector_api_key",
    ],
}

# -----------------------------
# AES-GCM (exact semantics you gave)
# -----------------------------
def aes_encrypt(plaintext: str, key: str, iv: str) -> str:
    key = bytes.fromhex(key)
    iv = bytes.fromhex(iv)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    enc = cipher.encryptor()
    ct = enc.update(plaintext.encode()) + enc.finalize()
    return base64.b64encode(ct + enc.tag).decode()


def aes_decrypt(ciphertext: str, key: str, iv: str) -> str:
    try:
        key = bytes.fromhex(key)
        iv = bytes.fromhex(iv)
        data = base64.b64decode(ciphertext)
        tag = data[-16:]
        ct = data[:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        return (dec.update(ct) + dec.finalize()).decode()
    except Exception:
        return ""

def aes_encrypt_crypto(plaintext: str, key: str, iv: str) -> str:
    try:
        key = bytes.fromhex(key)
        iv = bytes.fromhex(iv)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        enc = cipher.encryptor()
        ct = enc.update(plaintext.encode()) + enc.finalize()
        return base64.b64encode(ct + enc.tag).decode()
    except:
        return "Value Already Encrypted"


def aes_decrypt_crypto(ciphertext: str, key: str, iv: str) -> str:
    try:
        key = bytes.fromhex(key)
        iv = bytes.fromhex(iv)
        data = base64.b64decode(ciphertext)
        tag = data[-16:]
        ct = data[:-16]
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        dec = cipher.decryptor()
        return (dec.update(ct) + dec.finalize()).decode()
    except Exception:
        return "Value Already decrypted"

def decrypt_row(table: str, row):
    d = dict(row)
    for field in ENCRYPTED_COLUMNS.get(table, []):
        if d.get(field):
            d[field] = aes_decrypt(d[field], AES_KEY, AES_IV)
    return d


def encrypt_payload(table: str, data: dict):
    out = dict(data)
    for field in ENCRYPTED_COLUMNS.get(table, []):
        if out.get(field):
            out[field] = aes_encrypt(str(out[field]), AES_KEY, AES_IV)
    return out

# -----------------------------
# App + DB pool
# -----------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    global POOL
    print("Starting up... creating DB pool")

    POOL = await asyncpg.create_pool(
        host=DB_HOST,
        port=DB_PORT,
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASS,
        server_settings={"search_path": "public"},
        min_size=1,
        max_size=10,
    )

    yield  # App runs while this is active

    print("Shutting down... closing DB pool")
    if POOL:
        await POOL.close()

# Initialize FastAPI with the lifespan handler
app = FastAPI(title="Veremark Admin", lifespan=lifespan)
templates = Jinja2Templates(directory="templates")

# -----------------------------
# Root: force login then Home
# -----------------------------
@app.get("/", response_class=HTMLResponse)
async def root(_: bool = Depends(require_admin)):
    return RedirectResponse("/home", status_code=302)

@app.get("/home", response_class=HTMLResponse)
async def home(request: Request, _: bool = Depends(require_admin)):
    return templates.TemplateResponse("home.html", {"request": request, "title": "Home"})

# -----------------------------
# Platforms UI (list/create/edit/delete)
# -----------------------------
@app.get("/platforms", response_class=HTMLResponse)
async def platforms_list(request: Request, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        rows = await conn.fetch("""
            SELECT id, name, veremark_api_base_url, veremark_api_version, connector_api_key
            FROM platform ORDER BY name;
        """)
    data = [decrypt_row("platform", r) for r in rows]
    return templates.TemplateResponse("platforms_list.html", {"request": request, "platforms": data, "title": "Platforms"})

@app.get("/platforms/new", response_class=HTMLResponse)
async def platform_new(request: Request, _: bool = Depends(require_admin)):
    return templates.TemplateResponse("platform_form.html", {"request": request, "title": "New Platform", "p": None})

@app.get("/platforms/edit/{pid}", response_class=HTMLResponse)
async def platform_edit(pid: uuid.UUID, request: Request, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        row = await conn.fetchrow("""
            SELECT id, name, veremark_api_base_url, veremark_api_version, connector_api_key
            FROM platform WHERE id=$1
        """, pid)
    if not row: raise HTTPException(404, "Platform not found")
    p = decrypt_row("platform", row)
    return templates.TemplateResponse("platform_form.html", {"request": request, "title":"Edit Platform", "p": p})

@app.post("/platforms/save")
async def platform_save(
    _: bool = Depends(require_admin),
    id: Optional[str] = Form(None),
    name: str = Form(...),
    veremark_api_base_url: Optional[str] = Form(None),
    veremark_api_version: Optional[str] = Form(None),
    connector_api_key: Optional[str] = Form(None),
):
    payload = {
        "id": uuid.UUID(id) if id else uuid.uuid4(),
        "name": name.strip(),
        "veremark_api_base_url": veremark_api_base_url or None,
        "veremark_api_version": veremark_api_version or None,
        "connector_api_key": connector_api_key or None,
    }
    enc = encrypt_payload("platform", payload)

    async with POOL.acquire() as conn:
        exists = await conn.fetchval("SELECT 1 FROM platform WHERE id=$1", enc["id"])
        if exists:
            await conn.execute("""
                UPDATE platform SET
                    name=$1, veremark_api_base_url=$2, veremark_api_version=$3, connector_api_key=$4
                WHERE id=$5
            """, enc["name"], enc["veremark_api_base_url"], enc["veremark_api_version"], enc.get("connector_api_key"), enc["id"])
        else:
            await conn.execute("""
                INSERT INTO platform (id, name, veremark_api_base_url, veremark_api_version, connector_api_key)
                VALUES ($1,$2,$3,$4,$5)
            """, enc["id"], enc["name"], enc["veremark_api_base_url"], enc["veremark_api_version"], enc.get("connector_api_key"))
    return RedirectResponse("/platforms", status_code=303)

@app.post("/platforms/delete/{pid}")
async def platform_delete(pid: uuid.UUID, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        await conn.execute("DELETE FROM platform WHERE id=$1", pid)
    return RedirectResponse("/platforms", status_code=303)

# -----------------------------
# Tenants UI (list/create/edit/delete)
# -----------------------------
TENANT_COLS = [
    "id","platform_id","name","platform_tenant_id","platform_api_base_url","platform_api_version",
    "platform_api_username","platform_api_password","connector_platform_username","connector_platform_password",
    "veremark_api_token","connector_veremark_username","connector_veremark_password",
    "platform_document_category_mapping","platform_request_status_mapping",
    "platform_custom_report_url","connector_veremark_notification_url","platform_check_status_mapping",
]

@app.get("/tenants",response_class=HTMLResponse)
async def tenants_list(request: Request, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        rows = await conn.fetch("SELECT * FROM tenant ORDER BY name ASC")
        tenants = [decrypt_row("tenant", r) for r in rows]
    return templates.TemplateResponse("tenants_list.html", {"request": request, "tenants": tenants})


@app.get("/tenants/new", response_class=HTMLResponse)
async def tenant_new(request: Request, _: bool = Depends(require_admin)):
    return templates.TemplateResponse("tenant_form.html", {"request": request, "title": "New Tenant", "t": None})

@app.get("/tenants/edit/{tid}", response_class=HTMLResponse)
async def tenant_edit(tid: uuid.UUID, request: Request, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        row = await conn.fetchrow("SELECT " + ",".join(TENANT_COLS) + " FROM tenant WHERE id=$1", tid)
    if not row: raise HTTPException(404, "Tenant not found")
    t = decrypt_row("tenant", row)
    return templates.TemplateResponse("tenant_form.html", {"request": request, "title": "Edit Tenant", "t": t})

@app.post("/tenants/save")
async def tenant_save(request: Request, _: bool = Depends(require_admin)):
    form = await request.form()

    tenant_id = form.get("id") or None
    is_update = tenant_id is not None

    if not tenant_id:
        tenant_id = uuid.uuid4()

    payload = {
        "id": tenant_id,
        "platform_id": form.get("platform_id") or None,
        "name": form.get("name") or None,
        "platform_tenant_id": form.get("platform_tenant_id") or None,
        "platform_api_base_url": form.get("platform_api_base_url") or None,
        "platform_api_version": form.get("platform_api_version") or None,

        # encrypted
        "platform_api_username": form.get("platform_api_username") or None,
        "platform_api_password": form.get("platform_api_password") or None,
        "connector_platform_username": form.get("connector_platform_username") or None,
        "connector_platform_password": form.get("connector_platform_password") or None,
        "veremark_api_token": form.get("veremark_api_token") or None,
        "connector_veremark_username": form.get("connector_veremark_username") or None,
        "connector_veremark_password": form.get("connector_veremark_password") or None,

        # non-encrypted
        "platform_document_category_mapping": form.get("platform_document_category_mapping") or None,
        "platform_request_status_mapping": form.get("platform_request_status_mapping") or None,
        "platform_custom_report_url": form.get("platform_custom_report_url") or None,
        "connector_veremark_notification_url": form.get("connector_veremark_notification_url") or None,
        "platform_check_status_mapping": form.get("platform_check_status_mapping") or None,
    }

    # Encrypt before saving
    enc = encrypt_payload("tenant", payload)

    async with POOL.acquire() as conn:
        exists = await conn.fetchval("SELECT 1 FROM tenant WHERE id=$1", enc["id"])

        if exists:
            await conn.execute(
                """
                UPDATE tenant SET
                  platform_id=$1,
                  name=$2,
                  platform_tenant_id=$3,
                  platform_api_base_url=$4,
                  platform_api_version=$5,
                  platform_api_username=$6,
                  platform_api_password=$7,
                  connector_platform_username=$8,
                  connector_platform_password=$9,
                  veremark_api_token=$10,
                  connector_veremark_username=$11,
                  connector_veremark_password=$12,
                  platform_document_category_mapping=$13,
                  platform_request_status_mapping=$14,
                  platform_custom_report_url=$15,
                  connector_veremark_notification_url=$16,
                  platform_check_status_mapping=$17
                WHERE id=$18
                """,
                enc["platform_id"],
                enc["name"],
                enc["platform_tenant_id"],
                enc["platform_api_base_url"],
                enc["platform_api_version"],
                enc["platform_api_username"],
                enc["platform_api_password"],
                enc["connector_platform_username"],
                enc["connector_platform_password"],
                enc["veremark_api_token"],
                enc["connector_veremark_username"],
                enc["connector_veremark_password"],
                enc["platform_document_category_mapping"],
                enc["platform_request_status_mapping"],
                enc["platform_custom_report_url"],
                enc["connector_veremark_notification_url"],
                enc["platform_check_status_mapping"],
                enc["id"],
            )
        else:
            await conn.execute(
                """
                INSERT INTO tenant (
                  id, platform_id, name, platform_tenant_id,
                  platform_api_base_url, platform_api_version,
                  platform_api_username, platform_api_password,
                  connector_platform_username, connector_platform_password,
                  veremark_api_token, connector_veremark_username,
                  connector_veremark_password,
                  platform_document_category_mapping,
                  platform_request_status_mapping,
                  platform_custom_report_url,
                  connector_veremark_notification_url,
                  platform_check_status_mapping
                ) VALUES (
                  $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18
                )
                """,
                enc["id"],
                enc["platform_id"],
                enc["name"],
                enc["platform_tenant_id"],
                enc["platform_api_base_url"],
                enc["platform_api_version"],
                enc["platform_api_username"],
                enc["platform_api_password"],
                enc["connector_platform_username"],
                enc["connector_platform_password"],
                enc["veremark_api_token"],
                enc["connector_veremark_username"],
                enc["connector_veremark_password"],
                enc["platform_document_category_mapping"],
                enc["platform_request_status_mapping"],
                enc["platform_custom_report_url"],
                enc["connector_veremark_notification_url"],
                enc["platform_check_status_mapping"],
            )

    return RedirectResponse("/tenants", status_code=303)

@app.post("/tenants/delete/{tenant_id}")
async def tenant_delete(tenant_id: uuid.UUID, _: bool = Depends(require_admin)):
    async with POOL.acquire() as conn:
        result = await conn.execute("DELETE FROM tenant WHERE id = $1", tenant_id)
        # Optional: print to see what happened, e.g. "DELETE 1" or "DELETE 0"
        print("DELETE tenant:", tenant_id, "->", result)

    return RedirectResponse("/tenants", status_code=303)
# -----------------------------
# Swagger behind auth (optional)
# -----------------------------
from fastapi.openapi.docs import get_swagger_ui_html
@app.get("/docs", include_in_schema=False)
def docs(_: bool = Depends(require_admin)):
    return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")


@app.get("/crypto-tools")
async def crypto_tools_page(request: Request, _: bool = Depends(require_admin)):
    return templates.TemplateResponse("crypto_tools.html", {
        "request": request,
        "result": None,
        "input_value": "",
        "mode": "encrypt"
    })

# -----------------------------
# crypto-tools
# -----------------------------
@app.post("/crypto-tools")
async def crypto_tools_submit(request: Request, _: bool = Depends(require_admin)):
    form = await request.form()
    value = form.get("input_value") or ""
    mode = form.get("mode")

    result = ""
    error = None

    try:
        if mode == "encrypt":
            result = aes_encrypt_crypto(value, AES_KEY, AES_IV)
        elif mode == "decrypt":
            result = aes_decrypt_crypto(value, AES_KEY, AES_IV)
        else:
            error = "Invalid operation."
    except Exception as e:
        error = str(e)

    return templates.TemplateResponse("crypto_tools.html", {
        "request": request,
        "input_value": value,
        "mode": mode,
        "result": result,
        "error": error,
    })


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("dashboard:app", host="0.0.0.0", port=8000, reload=True)



