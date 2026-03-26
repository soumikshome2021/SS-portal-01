from fastapi import FastAPI, APIRouter, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import StreamingResponse, FileResponse
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from pydantic import BaseModel, Field, BeforeValidator, EmailStr
from typing import List, Optional, Annotated, Any
from datetime import datetime, timezone, timedelta
from pathlib import Path
import os, logging, uuid, httpx, io, asyncio, base64, hmac, hashlib
import razorpay as razorpay_lib
import resend
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, HRFlowable
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.enums import TA_LEFT, TA_RIGHT, TA_CENTER
from jose import JWTError, jwt
from passlib.context import CryptContext
from bson import ObjectId

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

mongo_url = os.environ["MONGO_URL"]
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ["DB_NAME"]]

JWT_SECRET = os.environ["JWT_SECRET"]
JWT_ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
JWT_EXPIRE_DAYS = int(os.environ.get("JWT_EXPIRE_DAYS", 7))
PAYPAL_CLIENT_ID = os.environ.get("PAYPAL_CLIENT_ID", "")
PAYPAL_SECRET = os.environ.get("PAYPAL_SECRET", "")
PAYPAL_MODE = os.environ.get("PAYPAL_MODE", "sandbox")
RAZORPAY_KEY_ID = os.environ.get("RAZORPAY_KEY_ID", "")
RAZORPAY_KEY_SECRET = os.environ.get("RAZORPAY_KEY_SECRET", "")
razorpay_client = razorpay_lib.Client(auth=(RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)) if RAZORPAY_KEY_ID else None

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
SENDER_EMAIL   = os.environ.get("SENDER_EMAIL", "onboarding@resend.dev")
if RESEND_API_KEY:
    resend.api_key = RESEND_API_KEY

app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ─── PyObjectId & BaseDocument ──────────────────────────────────────────────

def validate_object_id(v: Any) -> str:
    if isinstance(v, ObjectId):
        return str(v)
    return str(v)

PyObjectId = Annotated[str, BeforeValidator(validate_object_id)]

class BaseDocument(BaseModel):
    id: Optional[PyObjectId] = Field(alias="_id", default=None)

    model_config = {"populate_by_name": True}

    def to_mongo(self) -> dict:
        d = self.model_dump(exclude_none=True)
        d.pop("id", None)
        return d

    @classmethod
    def from_mongo(cls, doc: dict):
        if doc and "_id" in doc:
            doc["_id"] = str(doc["_id"])
        return cls(**doc)

# ─── Models ──────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserDB(BaseDocument):
    name: str
    email: str
    password_hash: str
    plan: str = "free"
    company: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class UserResponse(BaseDocument):
    name: str
    email: str
    plan: str
    company: Optional[str] = None
    phone: Optional[str] = None
    created_at: datetime

class UserUpdate(BaseModel):
    name: Optional[str] = None
    company: Optional[str] = None
    phone: Optional[str] = None

class ClientCreate(BaseModel):
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    address: Optional[str] = None

class ClientDB(BaseDocument):
    user_id: str
    name: str
    email: Optional[str] = None
    phone: Optional[str] = None
    company: Optional[str] = None
    address: Optional[str] = None
    status: str = "active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ProjectCreate(BaseModel):
    title: str
    client_id: Optional[str] = None
    description: Optional[str] = None
    status: str = "active"
    budget: Optional[float] = None
    currency: str = "USD"
    start_date: Optional[str] = None
    end_date: Optional[str] = None

class ProjectDB(BaseDocument):
    user_id: str
    title: str
    client_id: Optional[str] = None
    description: Optional[str] = None
    status: str = "active"
    budget: Optional[float] = None
    currency: str = "USD"
    start_date: Optional[str] = None
    end_date: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class InvoiceItem(BaseModel):
    description: str
    quantity: float
    rate: float
    amount: float

class InvoiceCreate(BaseModel):
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    items: List[InvoiceItem]
    subtotal: float
    tax: float = 0
    total: float
    currency: str = "USD"
    due_date: Optional[str] = None
    notes: Optional[str] = None

class InvoiceDB(BaseDocument):
    user_id: str
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    invoice_number: str
    items: List[InvoiceItem]
    subtotal: float
    tax: float = 0
    total: float
    currency: str = "USD"
    status: str = "draft"
    due_date: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class ContractCreate(BaseModel):
    title: str
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    content: str
    type: str = "contract"

class ContractDB(BaseDocument):
    user_id: str
    client_id: Optional[str] = None
    project_id: Optional[str] = None
    title: str
    content: str
    type: str = "contract"
    status: str = "draft"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

class StatusUpdate(BaseModel):
    status: str

# ─── Auth Helpers ─────────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

def create_token(user_id: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(days=JWT_EXPIRE_DAYS)
    return jwt.encode({"sub": user_id, "exp": expire}, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    doc = await db.users.find_one({"_id": user_id})
    if not doc:
        raise HTTPException(status_code=401, detail="User not found")
    return UserDB.from_mongo(doc)

async def get_next_invoice_number(user_id: str) -> str:
    count = await db.invoices.count_documents({"user_id": user_id})
    return f"INV-{str(count + 1).zfill(4)}"

# ─── Auth Routes ──────────────────────────────────────────────────────────────

@api_router.post("/auth/register")
async def register(data: UserCreate):
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_id = str(uuid.uuid4())
    user = UserDB(
        _id=user_id,
        name=data.name,
        email=data.email,
        password_hash=hash_password(data.password)
    )
    doc = user.to_mongo()
    doc["_id"] = user_id
    doc["created_at"] = doc["created_at"].isoformat()
    await db.users.insert_one(doc)
    token = create_token(user_id)
    return {"token": token, "user": {"id": user_id, "name": user.name, "email": user.email, "plan": user.plan}}

@api_router.post("/auth/login")
async def login(data: UserLogin):
    doc = await db.users.find_one({"email": data.email})
    if not doc or not verify_password(data.password, doc.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    token = create_token(str(doc["_id"]))
    return {"token": token, "user": {"id": str(doc["_id"]), "name": doc["name"], "email": doc["email"], "plan": doc.get("plan", "free")}}

@api_router.get("/auth/me")
async def me(user: UserDB = Depends(get_current_user)):
    doc = await db.users.find_one({"_id": user.id})
    return {"id": str(doc["_id"]), "name": doc["name"], "email": doc["email"], "plan": doc.get("plan", "free"), "company": doc.get("company"), "phone": doc.get("phone")}

# ─── User Routes ──────────────────────────────────────────────────────────────

@api_router.put("/users/profile")
async def update_profile(data: UserUpdate, user: UserDB = Depends(get_current_user)):
    update = {k: v for k, v in data.model_dump().items() if v is not None}
    await db.users.update_one({"_id": user.id}, {"$set": update})
    return {"message": "Profile updated"}

# ─── Dashboard Routes ─────────────────────────────────────────────────────────

@api_router.get("/dashboard/stats")
async def dashboard_stats(user: UserDB = Depends(get_current_user)):
    uid = user.id
    total_clients = await db.clients.count_documents({"user_id": uid, "status": "active"})
    total_projects = await db.projects.count_documents({"user_id": uid, "status": "active"})
    pending_invoices = await db.invoices.count_documents({"user_id": uid, "status": {"$in": ["sent", "draft"]}})
    paid_invoices = await db.invoices.find({"user_id": uid, "status": "paid"}).to_list(1000)
    total_earnings = sum(inv.get("total", 0) for inv in paid_invoices)
    recent_invoices = await db.invoices.find({"user_id": uid}).sort("created_at", -1).limit(5).to_list(5)
    recent_projects = await db.projects.find({"user_id": uid}).sort("created_at", -1).limit(5).to_list(5)

    # Monthly earnings for chart (last 6 months)
    monthly = {}
    for inv in paid_invoices:
        try:
            created = inv.get("created_at", "")
            if isinstance(created, str):
                dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
            else:
                dt = created
            key = dt.strftime("%b %Y")
            monthly[key] = monthly.get(key, 0) + inv.get("total", 0)
        except Exception:
            pass

    def clean_doc(doc):
        doc["_id"] = str(doc["_id"])
        return doc

    return {
        "total_clients": total_clients,
        "total_projects": total_projects,
        "pending_invoices": pending_invoices,
        "total_earnings": total_earnings,
        "recent_invoices": [clean_doc(i) for i in recent_invoices],
        "recent_projects": [clean_doc(p) for p in recent_projects],
        "monthly_earnings": [{"month": k, "amount": v} for k, v in monthly.items()]
    }

# ─── Client Routes ────────────────────────────────────────────────────────────

@api_router.get("/clients")
async def get_clients(user: UserDB = Depends(get_current_user)):
    docs = await db.clients.find({"user_id": user.id}).sort("created_at", -1).to_list(1000)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs

@api_router.post("/clients")
async def create_client(data: ClientCreate, user: UserDB = Depends(get_current_user)):
    cid = str(uuid.uuid4())
    client_obj = ClientDB(_id=cid, user_id=user.id, **data.model_dump())
    doc = client_obj.to_mongo()
    doc["_id"] = cid
    doc["created_at"] = doc["created_at"].isoformat()
    await db.clients.insert_one(doc)
    doc["_id"] = cid
    return doc

@api_router.put("/clients/{client_id}")
async def update_client(client_id: str, data: ClientCreate, user: UserDB = Depends(get_current_user)):
    await db.clients.update_one({"_id": client_id, "user_id": user.id}, {"$set": data.model_dump()})
    return {"message": "Updated"}

@api_router.delete("/clients/{client_id}")
async def delete_client(client_id: str, user: UserDB = Depends(get_current_user)):
    await db.clients.delete_one({"_id": client_id, "user_id": user.id})
    return {"message": "Deleted"}

# ─── Project Routes ───────────────────────────────────────────────────────────

@api_router.get("/projects")
async def get_projects(user: UserDB = Depends(get_current_user)):
    docs = await db.projects.find({"user_id": user.id}).sort("created_at", -1).to_list(1000)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs

@api_router.post("/projects")
async def create_project(data: ProjectCreate, user: UserDB = Depends(get_current_user)):
    pid = str(uuid.uuid4())
    project = ProjectDB(_id=pid, user_id=user.id, **data.model_dump())
    doc = project.to_mongo()
    doc["_id"] = pid
    doc["created_at"] = doc["created_at"].isoformat()
    await db.projects.insert_one(doc)
    doc["_id"] = pid
    return doc

@api_router.put("/projects/{project_id}")
async def update_project(project_id: str, data: ProjectCreate, user: UserDB = Depends(get_current_user)):
    await db.projects.update_one({"_id": project_id, "user_id": user.id}, {"$set": data.model_dump()})
    return {"message": "Updated"}

@api_router.put("/projects/{project_id}/status")
async def update_project_status(project_id: str, data: StatusUpdate, user: UserDB = Depends(get_current_user)):
    await db.projects.update_one({"_id": project_id, "user_id": user.id}, {"$set": {"status": data.status}})
    return {"message": "Updated"}

@api_router.delete("/projects/{project_id}")
async def delete_project(project_id: str, user: UserDB = Depends(get_current_user)):
    await db.projects.delete_one({"_id": project_id, "user_id": user.id})
    return {"message": "Deleted"}

# ─── Invoice Routes ───────────────────────────────────────────────────────────

@api_router.get("/invoices")
async def get_invoices(user: UserDB = Depends(get_current_user)):
    docs = await db.invoices.find({"user_id": user.id}).sort("created_at", -1).to_list(1000)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs

@api_router.post("/invoices")
async def create_invoice(data: InvoiceCreate, user: UserDB = Depends(get_current_user)):
    inv_id = str(uuid.uuid4())
    inv_num = await get_next_invoice_number(user.id)
    invoice = InvoiceDB(_id=inv_id, user_id=user.id, invoice_number=inv_num, **data.model_dump())
    doc = invoice.to_mongo()
    doc["_id"] = inv_id
    doc["created_at"] = doc["created_at"].isoformat()
    await db.invoices.insert_one(doc)
    doc["_id"] = inv_id
    return doc

@api_router.put("/invoices/{invoice_id}/status")
async def update_invoice_status(invoice_id: str, data: StatusUpdate, user: UserDB = Depends(get_current_user)):
    await db.invoices.update_one({"_id": invoice_id, "user_id": user.id}, {"$set": {"status": data.status}})
    return {"message": "Updated"}

@api_router.delete("/invoices/{invoice_id}")
async def delete_invoice(invoice_id: str, user: UserDB = Depends(get_current_user)):
    await db.invoices.delete_one({"_id": invoice_id, "user_id": user.id})
    return {"message": "Deleted"}

@api_router.get("/invoices/{invoice_id}/pdf")
async def download_invoice_pdf(invoice_id: str, user: UserDB = Depends(get_current_user)):
    inv = await db.invoices.find_one({"_id": invoice_id, "user_id": user.id})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    inv["_id"] = str(inv["_id"])
    client_doc = await db.clients.find_one({"_id": inv["client_id"]}) if inv.get("client_id") else None
    user_doc   = await db.users.find_one({"_id": user.id})
    buffer = io.BytesIO()
    _build_invoice_pdf(buffer, inv, client_doc, user_doc)
    buffer.seek(0)
    inv_num = inv.get("invoice_number", "invoice").replace("/", "-")
    return StreamingResponse(buffer, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{inv_num}.pdf"'})

class SendInvoiceRequest(BaseModel):
    recipient_email: EmailStr

@api_router.post("/invoices/{invoice_id}/send-email")
async def send_invoice_email(invoice_id: str, body: SendInvoiceRequest, user: UserDB = Depends(get_current_user)):
    if not RESEND_API_KEY:
        raise HTTPException(status_code=400, detail="Email service not configured")

    inv = await db.invoices.find_one({"_id": invoice_id, "user_id": user.id})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    inv["_id"] = str(inv["_id"])

    client_doc = None
    if inv.get("client_id"):
        client_doc = await db.clients.find_one({"_id": inv["client_id"]})
    user_doc = await db.users.find_one({"_id": user.id})

    # Generate PDF bytes
    pdf_buffer = io.BytesIO()
    _build_invoice_pdf(pdf_buffer, inv, client_doc, user_doc)
    pdf_buffer.seek(0)
    pdf_bytes = pdf_buffer.read()
    pdf_b64 = base64.b64encode(pdf_bytes).decode("utf-8")

    inv_num     = inv.get("invoice_number", "Invoice")
    total       = inv.get("total", 0) or 0
    due_date    = inv.get("due_date") or "N/A"
    sender_name = user_doc.get("name", "SS Portal") if user_doc else "SS Portal"
    sender_co   = user_doc.get("company", "") if user_doc else ""
    client_name = client_doc.get("name", "there") if client_doc else "there"

    items_rows = "".join([
        f"""<tr style="border-bottom:1px solid #E5E3DF;">
              <td style="padding:8px 12px;color:#1A1D18;font-size:14px;">{it.get('description','')}</td>
              <td style="padding:8px 12px;text-align:right;color:#5C6359;font-size:14px;">{it.get('quantity','')}</td>
              <td style="padding:8px 12px;text-align:right;color:#5C6359;font-size:14px;">${it.get('rate',0):,.2f}</td>
              <td style="padding:8px 12px;text-align:right;font-weight:600;color:#1A1D18;font-size:14px;">${it.get('amount',0):,.2f}</td>
            </tr>"""
        for it in inv.get("items", [])
    ])

    html_body = f"""
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F9F8F6;font-family:'Helvetica Neue',Helvetica,Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F9F8F6;padding:40px 0;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #E5E3DF;">

        <!-- Header -->
        <tr style="background:#2B4C3B;">
          <td style="padding:32px 40px;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <span style="color:#ffffff;font-size:22px;font-weight:900;letter-spacing:-0.5px;">SS Portal</span><br>
                  <span style="color:rgba(255,255,255,0.7);font-size:12px;">{sender_name}{(' · ' + sender_co) if sender_co else ''}</span>
                </td>
                <td align="right">
                  <span style="background:#D96C4A;color:#ffffff;font-size:11px;font-weight:700;padding:6px 14px;border-radius:999px;letter-spacing:0.5px;">INVOICE</span>
                </td>
              </tr>
            </table>
          </td>
        </tr>

        <!-- Invoice Meta -->
        <tr>
          <td style="padding:32px 40px 0;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td>
                  <p style="margin:0 0 4px;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;">Invoice Number</p>
                  <p style="margin:0;font-size:20px;font-weight:800;color:#2B4C3B;">{inv_num}</p>
                </td>
                <td align="right">
                  <p style="margin:0 0 4px;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;">Amount Due</p>
                  <p style="margin:0;font-size:28px;font-weight:900;color:#1A1D18;">${total:,.2f}</p>
                </td>
              </tr>
            </table>
            <p style="margin:16px 0 0;font-size:13px;color:#5C6359;">Due Date: <strong style="color:#1A1D18;">{due_date}</strong></p>
          </td>
        </tr>

        <!-- Greeting -->
        <tr>
          <td style="padding:24px 40px 0;">
            <p style="margin:0;font-size:15px;color:#1A1D18;line-height:1.6;">
              Hi <strong>{client_name}</strong>,<br><br>
              Please find your invoice <strong>{inv_num}</strong> attached as a PDF to this email.
              Here's a summary of the services provided:
            </p>
          </td>
        </tr>

        <!-- Line Items -->
        <tr>
          <td style="padding:24px 40px 0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #E5E3DF;border-radius:8px;overflow:hidden;">
              <tr style="background:#F9F8F6;">
                <th style="padding:10px 12px;text-align:left;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;font-weight:600;">Description</th>
                <th style="padding:10px 12px;text-align:right;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;font-weight:600;">Qty</th>
                <th style="padding:10px 12px;text-align:right;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;font-weight:600;">Rate</th>
                <th style="padding:10px 12px;text-align:right;font-size:11px;color:#5C6359;text-transform:uppercase;letter-spacing:0.1em;font-weight:600;">Amount</th>
              </tr>
              {items_rows}
            </table>
          </td>
        </tr>

        <!-- Totals -->
        <tr>
          <td style="padding:16px 40px 0;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td style="text-align:right;padding:4px 0;font-size:13px;color:#5C6359;">Subtotal</td>
                <td width="100" style="text-align:right;padding:4px 0;font-size:13px;color:#1A1D18;">${inv.get('subtotal',0):,.2f}</td>
              </tr>
              <tr>
                <td style="text-align:right;padding:4px 0;font-size:13px;color:#5C6359;">Tax</td>
                <td style="text-align:right;padding:4px 0;font-size:13px;color:#1A1D18;">${inv.get('tax',0):,.2f}</td>
              </tr>
              <tr style="border-top:2px solid #2B4C3B;">
                <td style="text-align:right;padding:10px 0 4px;font-size:16px;font-weight:800;color:#2B4C3B;">Total Due</td>
                <td style="text-align:right;padding:10px 0 4px;font-size:16px;font-weight:900;color:#2B4C3B;">${total:,.2f}</td>
              </tr>
            </table>
          </td>
        </tr>

        {f'<tr><td style="padding:16px 40px 0;"><p style="margin:0;font-size:13px;color:#5C6359;font-style:italic;">{inv["notes"]}</p></td></tr>' if inv.get("notes") else ""}

        <!-- CTA -->
        <tr>
          <td style="padding:32px 40px;">
            <p style="margin:0 0 16px;font-size:14px;color:#5C6359;">The PDF invoice is attached to this email for your records. You can also view and approve this invoice online through your client portal.</p>
            <a href="{os.environ.get('REACT_APP_PORTAL_URL', '')}/client" style="display:inline-block;background:#2B4C3B;color:#ffffff;font-size:13px;font-weight:700;padding:12px 24px;border-radius:999px;text-decoration:none;">View in Client Portal</a>
            <p style="margin:20px 0 0;font-size:14px;color:#1A1D18;">Thank you for your business!</p>
            <p style="margin:8px 0 0;font-size:14px;font-weight:600;color:#2B4C3B;">{sender_name}</p>
          </td>
        </tr>

        <!-- Footer -->
        <tr style="background:#F9F8F6;border-top:1px solid #E5E3DF;">
          <td style="padding:20px 40px;text-align:center;">
            <p style="margin:0;font-size:11px;color:#5C6359;">Sent via <strong>SS Portal</strong> · Professional Freelancer Management</p>
          </td>
        </tr>

      </table>
    </td></tr>
  </table>
</body>
</html>"""

    params = {
        "from": SENDER_EMAIL,
        "to": [body.recipient_email],
        "subject": f"Invoice {inv_num} from {sender_name} — ${total:,.2f} due {due_date}",
        "html": html_body,
        "attachments": [{"filename": f"{inv_num}.pdf", "content": list(pdf_bytes)}],
    }

    try:
        result = await asyncio.to_thread(resend.Emails.send, params)
        # Mark invoice as "sent"
        await db.invoices.update_one({"_id": invoice_id}, {"$set": {"status": "sent"}})
        return {"message": "Invoice sent successfully", "email_id": result.get("id")}
    except Exception as e:
        logger.error(f"Resend error: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to send email: {str(e)}")


def _build_invoice_pdf(buffer: io.BytesIO, inv: dict, client_doc, user_doc) -> None:
    """Shared PDF builder used by both download and email endpoints."""
    doc = SimpleDocTemplate(
        buffer, pagesize=A4,
        leftMargin=20*mm, rightMargin=20*mm,
        topMargin=20*mm, bottomMargin=20*mm
    )
    PRIMARY  = colors.HexColor("#2B4C3B")
    BG_LIGHT = colors.HexColor("#F9F8F6")
    BORDER   = colors.HexColor("#E5E3DF")
    MUTED    = colors.HexColor("#5C6359")

    styles = getSampleStyleSheet()
    def style(name, **kw):
        return ParagraphStyle(name, parent=styles["Normal"], **kw)

    s_logo    = style("logo2",   fontSize=22, textColor=PRIMARY, fontName="Helvetica-Bold", spaceAfter=2)
    s_title   = style("title2",  fontSize=26, textColor=PRIMARY, fontName="Helvetica-Bold", spaceAfter=4)
    s_label   = style("label2",  fontSize=8,  textColor=MUTED,   fontName="Helvetica", spaceAfter=1)
    s_value   = style("value2",  fontSize=10, textColor=colors.HexColor("#1A1D18"), fontName="Helvetica-Bold")
    s_body    = style("body2",   fontSize=9,  textColor=colors.HexColor("#1A1D18"), fontName="Helvetica")
    s_note    = style("note2",   fontSize=8,  textColor=MUTED,   fontName="Helvetica-Oblique")
    s_th      = style("th2",     fontSize=8,  textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_LEFT)
    s_td      = style("td2",     fontSize=9,  textColor=colors.HexColor("#1A1D18"), fontName="Helvetica")
    s_td_r    = style("td_r2",   fontSize=9,  textColor=colors.HexColor("#1A1D18"), fontName="Helvetica", alignment=TA_RIGHT)
    s_total_l = style("totl2",   fontSize=10, textColor=MUTED,   fontName="Helvetica-Bold", alignment=TA_RIGHT)
    s_total_v = style("totv2",   fontSize=10, textColor=colors.HexColor("#1A1D18"), fontName="Helvetica-Bold", alignment=TA_RIGHT)
    s_grand_l = style("grandl2", fontSize=12, textColor=PRIMARY, fontName="Helvetica-Bold", alignment=TA_RIGHT)
    s_grand_v = style("grandv2", fontSize=12, textColor=PRIMARY, fontName="Helvetica-Bold", alignment=TA_RIGHT)

    story  = []
    page_w = A4[0] - 40*mm
    sender_name = user_doc.get("name", "SS Portal User") if user_doc else "SS Portal User"
    sender_co   = user_doc.get("company", "") if user_doc else ""

    # Header
    ht = Table([[Paragraph("SS Portal", s_logo), Paragraph("INVOICE", s_title)]], colWidths=[page_w*0.5, page_w*0.5])
    ht.setStyle(TableStyle([("ALIGN",(0,0),(0,0),"LEFT"),("ALIGN",(1,0),(1,0),"RIGHT"),("VALIGN",(0,0),(-1,-1),"MIDDLE")]))
    story.append(ht)

    inv_date     = inv.get("created_at", "")[:10] if inv.get("created_at") else ""
    inv_due      = inv.get("due_date", "") or "—"
    status_label = inv.get("status", "draft").upper()
    status_color = {"PAID": colors.HexColor("#16a34a"), "OVERDUE": colors.HexColor("#dc2626"),
                    "SENT": colors.HexColor("#2563eb")}.get(status_label, MUTED)

    mt = Table([[Paragraph(f"{sender_name}<br/>{sender_co}", s_body),
                 Paragraph(status_label, style("st2", fontSize=11, fontName="Helvetica-Bold", alignment=TA_RIGHT, textColor=status_color))]],
               colWidths=[page_w*0.5, page_w*0.5])
    mt.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP")]))
    story.extend([Spacer(1,4*mm), mt, Spacer(1,2*mm), HRFlowable(width="100%",thickness=1,color=BORDER), Spacer(1,5*mm)])

    # Bill To / Invoice Details
    client_name  = client_doc.get("name","—")    if client_doc else "—"
    client_email = client_doc.get("email","")    if client_doc else ""
    client_co    = client_doc.get("company","")   if client_doc else ""
    client_addr  = client_doc.get("address","")   if client_doc else ""
    bill_info    = client_name
    if client_co:    bill_info += f"<br/>{client_co}"
    if client_email: bill_info += f"<br/>{client_email}"
    if client_addr:  bill_info += f"<br/>{client_addr}"

    dt = Table([[
        Paragraph(f"<b>BILL TO</b><br/>{bill_info}", style("bt2", fontSize=9, fontName="Helvetica", textColor=colors.HexColor("#1A1D18"), leading=14)),
        Table([[Paragraph("Invoice No", s_label), Paragraph(inv.get("invoice_number","—"), s_value)],
               [Paragraph("Date Issued", s_label), Paragraph(inv_date, s_body)],
               [Paragraph("Due Date", s_label), Paragraph(inv_due, s_body)]],
              colWidths=[page_w*0.2, page_w*0.3],
              style=TableStyle([("TOPPADDING",(0,0),(-1,-1),2),("BOTTOMPADDING",(0,0),(-1,-1),2),("ALIGN",(1,0),(1,-1),"RIGHT")]))
    ]], colWidths=[page_w*0.5, page_w*0.5])
    dt.setStyle(TableStyle([("VALIGN",(0,0),(-1,-1),"TOP")]))
    story.extend([dt, Spacer(1,6*mm)])

    # Line Items
    items     = inv.get("items", [])
    col_w     = [page_w*0.5, page_w*0.15, page_w*0.17, page_w*0.18]
    tdata     = [[Paragraph("DESCRIPTION", s_th),
                  Paragraph("QTY",    style("thr",  fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_RIGHT)),
                  Paragraph("RATE",   style("thr2", fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_RIGHT)),
                  Paragraph("AMOUNT", style("thr3", fontSize=8, textColor=colors.white, fontName="Helvetica-Bold", alignment=TA_RIGHT))]]
    for it in items:
        tdata.append([Paragraph(it.get("description",""), s_td),
                      Paragraph(str(it.get("quantity","")), s_td_r),
                      Paragraph(f"${it.get('rate',0):,.2f}", s_td_r),
                      Paragraph(f"${it.get('amount',0):,.2f}", s_td_r)])
    itbl = Table(tdata, colWidths=col_w, repeatRows=1)
    itbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),PRIMARY),("ROWBACKGROUNDS",(0,1),(-1,-1),[colors.white,BG_LIGHT]),
        ("ALIGN",(1,0),(-1,-1),"RIGHT"),("TOPPADDING",(0,0),(-1,-1),6),("BOTTOMPADDING",(0,0),(-1,-1),6),
        ("LEFTPADDING",(0,0),(-1,-1),8),("RIGHTPADDING",(0,0),(-1,-1),8),("GRID",(0,0),(-1,-1),0.5,BORDER),
    ]))
    story.extend([itbl, Spacer(1,4*mm)])

    # Totals
    subtotal = inv.get("subtotal",0) or 0
    tax      = inv.get("tax",0) or 0
    total    = inv.get("total",0) or 0
    ttbl = Table([[Paragraph("Subtotal",  s_total_l), Paragraph(f"${subtotal:,.2f}", s_total_v)],
                  [Paragraph("Tax",       s_total_l), Paragraph(f"${tax:,.2f}",      s_total_v)],
                  [Paragraph("TOTAL DUE", s_grand_l), Paragraph(f"${total:,.2f}",    s_grand_v)]],
                 colWidths=[page_w*0.8, page_w*0.2])
    ttbl.setStyle(TableStyle([("ALIGN",(0,0),(-1,-1),"RIGHT"),("TOPPADDING",(0,0),(-1,-1),3),
        ("BOTTOMPADDING",(0,0),(-1,-1),3),("LINEABOVE",(0,2),(-1,2),1,PRIMARY),("TOPPADDING",(0,2),(-1,2),6)]))
    story.append(ttbl)

    if inv.get("notes"):
        story.extend([Spacer(1,6*mm), HRFlowable(width="100%",thickness=0.5,color=BORDER),
                      Spacer(1,3*mm), Paragraph("Notes", s_label), Paragraph(inv["notes"], s_note)])

    story.extend([Spacer(1,10*mm), HRFlowable(width="100%",thickness=0.5,color=BORDER), Spacer(1,3*mm),
                  Paragraph("Generated by SS Portal — ssportal.com",
                             style("footer2", fontSize=8, textColor=MUTED, alignment=TA_CENTER))])
    doc.build(story)

@api_router.get("/contracts")
async def get_contracts(user: UserDB = Depends(get_current_user)):
    docs = await db.contracts.find({"user_id": user.id}).sort("created_at", -1).to_list(1000)
    for d in docs:
        d["_id"] = str(d["_id"])
    return docs

@api_router.post("/contracts")
async def create_contract(data: ContractCreate, user: UserDB = Depends(get_current_user)):
    cid = str(uuid.uuid4())
    contract = ContractDB(_id=cid, user_id=user.id, **data.model_dump())
    doc = contract.to_mongo()
    doc["_id"] = cid
    doc["created_at"] = doc["created_at"].isoformat()
    await db.contracts.insert_one(doc)
    doc["_id"] = cid
    return doc

@api_router.put("/contracts/{contract_id}/status")
async def update_contract_status(contract_id: str, data: StatusUpdate, user: UserDB = Depends(get_current_user)):
    await db.contracts.update_one({"_id": contract_id, "user_id": user.id}, {"$set": {"status": data.status}})
    return {"message": "Updated"}

@api_router.delete("/contracts/{contract_id}")
async def delete_contract(contract_id: str, user: UserDB = Depends(get_current_user)):
    await db.contracts.delete_one({"_id": contract_id, "user_id": user.id})
    return {"message": "Deleted"}

# ─── PayPal Routes ────────────────────────────────────────────────────────────

PAYPAL_BASE = "https://api-m.sandbox.paypal.com" if PAYPAL_MODE == "sandbox" else "https://api-m.paypal.com"

async def get_paypal_token() -> str:
    async with httpx.AsyncClient() as hclient:
        r = await hclient.post(
            f"{PAYPAL_BASE}/v1/oauth2/token",
            auth=(PAYPAL_CLIENT_ID, PAYPAL_SECRET),
            data={"grant_type": "client_credentials"}
        )
        return r.json().get("access_token", "")

@api_router.post("/paypal/create-order")
async def create_paypal_order(body: dict, user: UserDB = Depends(get_current_user)):
    if not PAYPAL_CLIENT_ID:
        raise HTTPException(status_code=400, detail="PayPal not configured")
    token = await get_paypal_token()
    plan = body.get("plan", "solo")
    amount = "15.00" if plan == "solo" else "59.00"
    frontend_url = os.environ.get("FRONTEND_URL", "https://no-ai-zone-2.preview.emergentagent.com")
    async with httpx.AsyncClient() as hclient:
        r = await hclient.post(
            f"{PAYPAL_BASE}/v2/checkout/orders",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={
                "intent": "CAPTURE",
                "purchase_units": [{"amount": {"currency_code": "USD", "value": amount}, "description": f"SS Portal {plan.capitalize()} Plan"}],
                "application_context": {
                    "return_url": f"{frontend_url}/payment-success?plan={plan}",
                    "cancel_url": f"{frontend_url}/subscription",
                    "brand_name": "SS Portal",
                    "user_action": "PAY_NOW"
                }
            }
        )
    return r.json()

@api_router.post("/paypal/capture-order/{order_id}")
async def capture_paypal_order(order_id: str, body: dict, user: UserDB = Depends(get_current_user)):
    if not PAYPAL_CLIENT_ID:
        raise HTTPException(status_code=400, detail="PayPal not configured")
    token = await get_paypal_token()
    async with httpx.AsyncClient() as hclient:
        r = await hclient.post(
            f"{PAYPAL_BASE}/v2/checkout/orders/{order_id}/capture",
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={}
        )
    result = r.json()
    if result.get("status") == "COMPLETED":
        plan = body.get("plan", "solo")
        await db.users.update_one({"_id": user.id}, {"$set": {"plan": plan}})
    return result

# ─── Client Portal Routes ─────────────────────────────────────────────────────

class ClientPortalLogin(BaseModel):
    email: EmailStr

@api_router.post("/client-portal/access")
async def client_portal_access(data: ClientPortalLogin):
    # Find client by email across all users
    doc = await db.clients.find_one({"email": data.email})
    if not doc:
        raise HTTPException(status_code=404, detail="No account found with this email address")
    token = create_token(f"client:{str(doc['_id'])}")
    return {"token": token, "client": {"id": str(doc["_id"]), "name": doc["name"], "email": doc["email"]}}

async def get_portal_client(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        sub = payload.get("sub", "")
        if not sub.startswith("client:"):
            raise HTTPException(status_code=401, detail="Invalid portal token")
        client_id = sub.replace("client:", "")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")
    doc = await db.clients.find_one({"_id": client_id})
    if not doc:
        raise HTTPException(status_code=401, detail="Client not found")
    return doc

@api_router.get("/client-portal/invoices")
async def client_portal_invoices(client=Depends(get_portal_client)):
    cid = str(client["_id"])
    docs = await db.invoices.find({"client_id": cid}).sort("created_at", -1).to_list(200)
    # Attach freelancer name to each invoice
    result = []
    for d in docs:
        d["_id"] = str(d["_id"])
        owner = await db.users.find_one({"_id": d.get("user_id", "")})
        d["freelancer_name"] = owner.get("name", "SS Portal") if owner else "SS Portal"
        d["freelancer_company"] = owner.get("company", "") if owner else ""
        result.append(d)
    return result

@api_router.put("/client-portal/invoices/{invoice_id}/approve")
async def client_portal_approve(invoice_id: str, client=Depends(get_portal_client)):
    inv = await db.invoices.find_one({"_id": invoice_id, "client_id": str(client["_id"])})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    await db.invoices.update_one({"_id": invoice_id}, {"$set": {"status": "paid"}})
    return {"message": "Invoice approved"}

@api_router.get("/client-portal/download/{invoice_id}")
async def client_portal_download_pdf(invoice_id: str, client=Depends(get_portal_client)):
    inv = await db.invoices.find_one({"_id": invoice_id, "client_id": str(client["_id"])})
    if not inv:
        raise HTTPException(status_code=404, detail="Invoice not found")
    inv["_id"] = str(inv["_id"])
    client_doc = await db.clients.find_one({"_id": str(client["_id"])})
    user_doc   = await db.users.find_one({"_id": inv.get("user_id", "")})
    buffer = io.BytesIO()
    _build_invoice_pdf(buffer, inv, client_doc, user_doc)
    buffer.seek(0)
    inv_num = inv.get("invoice_number", "invoice").replace("/", "-")
    return StreamingResponse(buffer, media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{inv_num}.pdf"'})

# ─── Razorpay Routes ──────────────────────────────────────────────────────────

class RazorpayOrderRequest(BaseModel):
    plan: str

class RazorpayVerifyRequest(BaseModel):
    razorpay_order_id: str
    razorpay_payment_id: str
    razorpay_signature: str
    plan: str

@api_router.post("/razorpay/create-order")
async def create_razorpay_order(body: RazorpayOrderRequest, user: UserDB = Depends(get_current_user)):
    if not razorpay_client:
        raise HTTPException(status_code=400, detail="Razorpay not configured")
    amount = 129900 if body.plan == "solo" else 499900  # paise: ₹1299 or ₹4999
    try:
        order = await asyncio.to_thread(razorpay_client.order.create, {
            "amount": amount,
            "currency": "INR",
            "payment_capture": 1,
            "notes": {"plan": body.plan, "user_id": user.id}
        })
        return order
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@api_router.post("/razorpay/verify-payment")
async def verify_razorpay_payment(body: RazorpayVerifyRequest, user: UserDB = Depends(get_current_user)):
    if not razorpay_client:
        raise HTTPException(status_code=400, detail="Razorpay not configured")
    try:
        razorpay_client.utility.verify_payment_signature({
            "razorpay_order_id": body.razorpay_order_id,
            "razorpay_payment_id": body.razorpay_payment_id,
            "razorpay_signature": body.razorpay_signature
        })
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid payment signature")
    await db.users.update_one({"_id": user.id}, {"$set": {"plan": body.plan}})
    return {"status": "success", "plan": body.plan}

# ─── Download Route ───────────────────────────────────────────────────────────

@api_router.get("/download-source")
async def download_source():
    zip_path = "/app/ss_portal_complete.zip"
    if not os.path.exists(zip_path):
        raise HTTPException(status_code=404, detail="File not found")
    return FileResponse(zip_path, media_type="application/zip", filename="ss_portal_complete.zip")

# ─── App Setup ────────────────────────────────────────────────────────────────

app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
