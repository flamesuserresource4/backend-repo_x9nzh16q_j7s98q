import os
from datetime import datetime, timedelta
from io import BytesIO
from typing import Optional, Literal

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from passlib.context import CryptContext
import jwt

from database import db
from schemas import Customer, Vehicle, Payment, Shipping, User, Token, LoginRequest

from bson import ObjectId
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from openpyxl import Workbook
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText

# Security Config
JWT_SECRET = os.getenv("JWT_SECRET", "devsecret-change-me")
JWT_EXPIRES_MIN = int(os.getenv("JWT_EXPIRES_MIN", "240"))

# Use pbkdf2_sha256 to avoid bcrypt build/runtime issues
pwd_context = CryptContext(schemes=["pbkdf2_sha256"], deprecated="auto")
auth_scheme = HTTPBearer()


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(sub: str, role: str) -> str:
    payload = {
        "sub": sub,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRES_MIN),
        "iat": datetime.utcnow(),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm="HS256")


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(auth_scheme)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(status_code=401, detail="Invalid token")
        user = db["user"].find_one({"_id": ObjectId(user_id)}) if db is not None else None
        if not user or not user.get("is_active", True):
            raise HTTPException(status_code=401, detail="User inactive or not found")
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")


app = FastAPI(title="Pablo's Car - Sub-Customer Management API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def ensure_admin_user():
    # Create default admin if none exists
    if db is None:
        return
    admin_email = os.getenv("ADMIN_EMAIL", "admin@pabloscar.com")
    admin_pass = os.getenv("ADMIN_PASSWORD", "admin123")
    existing = db["user"].find_one({"email": admin_email})
    if not existing:
        db["user"].insert_one({
            "email": admin_email,
            "hashed_password": hash_password(admin_pass),
            "role": "admin",
            "full_name": "Admin",
            "is_active": True,
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        })


# -------- Auth --------
@app.post("/auth/login", response_model=Token)
def login(payload: LoginRequest):
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")
    user = db["user"].find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("hashed_password", "")):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(str(user["_id"]), user.get("role", "staff"))
    return {"access_token": token, "token_type": "bearer"}


# Utility functions

def oid(id_str: str) -> ObjectId:
    try:
        return ObjectId(id_str)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid id")


def ensure_db():
    if db is None:
        raise HTTPException(status_code=500, detail="Database not configured")


# -------- Customers --------
@app.get("/customers")
def list_customers(current=Depends(get_current_user)):
    ensure_db()
    docs = db["customer"].find().sort("created_at", -1)
    out = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        out.append(d)
    return out


@app.post("/customers")
def create_customer(payload: Customer, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    now = datetime.utcnow()
    data.update({"created_at": now, "updated_at": now})
    result = db["customer"].insert_one(data)
    return {"id": str(result.inserted_id)}


@app.put("/customers/{customer_id}")
def update_customer(customer_id: str, payload: Customer, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data["updated_at"] = datetime.utcnow()
    res = db["customer"].update_one({"_id": oid(customer_id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Customer not found")
    return {"status": "ok"}


@app.delete("/customers/{customer_id}")
def delete_customer(customer_id: str, current=Depends(get_current_user)):
    ensure_db()
    res = db["customer"].delete_one({"_id": oid(customer_id)})
    if res.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Customer not found")
    # Cascade delete vehicles/payments for this customer
    db["vehicle"].delete_many({"customer_id": customer_id})
    db["payment"].delete_many({"customer_id": customer_id})
    return {"status": "ok"}


# -------- Vehicles --------
@app.get("/vehicles")
def list_vehicles(customer_id: Optional[str] = None, current=Depends(get_current_user)):
    ensure_db()
    q = {"customer_id": customer_id} if customer_id else {}
    docs = db["vehicle"].find(q).sort("created_at", -1)
    out = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        out.append(d)
    return out


@app.post("/vehicles")
def create_vehicle(payload: Vehicle, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data.update({"created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    result = db["vehicle"].insert_one(data)
    return {"id": str(result.inserted_id)}


@app.put("/vehicles/{vehicle_id}")
def update_vehicle(vehicle_id: str, payload: Vehicle, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data["updated_at"] = datetime.utcnow()
    res = db["vehicle"].update_one({"_id": oid(vehicle_id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    return {"status": "ok"}


# -------- Payments --------
@app.get("/payments")
def list_payments(customer_id: Optional[str] = None, current=Depends(get_current_user)):
    ensure_db()
    q = {"customer_id": customer_id} if customer_id else {}
    docs = db["payment"].find(q).sort("payment_date", -1)
    out = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        out.append(d)
    return out


@app.post("/payments")
def create_payment(payload: Payment, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data.update({"created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    result = db["payment"].insert_one(data)
    return {"id": str(result.inserted_id)}


@app.put("/payments/{payment_id}")
def update_payment(payment_id: str, payload: Payment, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data["updated_at"] = datetime.utcnow()
    res = db["payment"].update_one({"_id": oid(payment_id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Payment not found")
    return {"status": "ok"}


# -------- Shipping --------
@app.get("/shipping")
def list_shipping(vehicle_id: Optional[str] = None, current=Depends(get_current_user)):
    ensure_db()
    q = {"vehicle_id": vehicle_id} if vehicle_id else {}
    docs = db["shipping"].find(q).sort("estimated_arrival", -1)
    out = []
    for d in docs:
        d["id"] = str(d.pop("_id"))
        out.append(d)
    return out


@app.post("/shipping")
def create_shipping(payload: Shipping, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data.update({"created_at": datetime.utcnow(), "updated_at": datetime.utcnow()})
    result = db["shipping"].insert_one(data)
    return {"id": str(result.inserted_id)}


@app.put("/shipping/{shipping_id}")
def update_shipping(shipping_id: str, payload: Shipping, current=Depends(get_current_user)):
    ensure_db()
    data = payload.model_dump()
    data["updated_at"] = datetime.utcnow()
    res = db["shipping"].update_one({"_id": oid(shipping_id)}, {"$set": data})
    if res.matched_count == 0:
        raise HTTPException(status_code=404, detail="Shipping not found")
    return {"status": "ok"}


# -------- Reports & Exports --------
@app.get("/reports")
def generate_report(report_type: Literal["customers", "vehicles", "payments", "shipping"]):
    ensure_db()
    wb = Workbook()
    ws = wb.active
    ws.title = report_type.capitalize()

    headers = []
    rows = []

    if report_type == "customers":
        headers = ["Full Name", "Passport", "DOB", "Address", "Phone", "Email", "Created"]
        for d in db["customer"].find():
            rows.append([
                d.get("full_name"), d.get("passport_number"), str(d.get("dob")), d.get("address"), d.get("phone"), d.get("email"), str(d.get("created_at"))
            ])
    elif report_type == "vehicles":
        headers = ["Customer ID", "Brand", "Model", "Variant", "VIN", "Purchase Date", "Price", "Payment Status"]
        for d in db["vehicle"].find():
            rows.append([
                d.get("customer_id"), d.get("brand"), d.get("model"), d.get("variant"), d.get("vin"), str(d.get("purchase_date")), d.get("price"), d.get("payment_status")
            ])
    elif report_type == "payments":
        headers = ["Customer ID", "Amount", "Type", "Status", "Payment Date"]
        for d in db["payment"].find():
            rows.append([
                d.get("customer_id"), d.get("amount"), d.get("payment_type"), d.get("payment_status"), str(d.get("payment_date"))
            ])
    elif report_type == "shipping":
        headers = ["Vehicle ID", "Container", "Company", "ETA", "Status"]
        for d in db["shipping"].find():
            rows.append([
                d.get("vehicle_id"), d.get("container_number"), d.get("shipping_company"), str(d.get("estimated_arrival")), d.get("status")
            ])

    ws.append(headers)
    for r in rows:
        ws.append(r)

    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)

    filename = f"{report_type}_report.xlsx"
    return StreamingResponse(bio, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename={filename}"})


def build_shipping_sheet_pdf(vehicle_id: str) -> BytesIO:
    ensure_db()
    v = db["vehicle"].find_one({"_id": oid(vehicle_id)})
    if not v:
        raise HTTPException(status_code=404, detail="Vehicle not found")
    # customer_id stored as string id
    c = None
    cid = v.get("customer_id")
    if cid:
        try:
            c = db["customer"].find_one({"_id": oid(cid)})
        except HTTPException:
            c = None
    s = db["shipping"].find_one({"vehicle_id": vehicle_id})
    payments = list(db["payment"].find({"customer_id": cid})) if cid else []

    bio = BytesIO()
    c_canvas = canvas.Canvas(bio, pagesize=A4)
    width, height = A4

    # Header
    c_canvas.setFont("Helvetica-Bold", 16)
    c_canvas.drawString(20 * mm, height - 20 * mm, "Pablo's Car - Shipping Sheet")
    c_canvas.setFont("Helvetica", 10)
    c_canvas.drawString(20 * mm, height - 27 * mm, f"Generated: {datetime.utcnow().isoformat()}Z")

    # Company Branding
    c_canvas.setFont("Helvetica-Bold", 12)
    c_canvas.drawString(20 * mm, height - 35 * mm, "Company: Pablo's Car")

    y = height - 50 * mm

    # Customer Details
    c_canvas.setFont("Helvetica-Bold", 12)
    c_canvas.drawString(20 * mm, y, "Customer Details")
    y -= 6 * mm
    c_canvas.setFont("Helvetica", 11)
    if c:
        c_canvas.drawString(20 * mm, y, f"Name: {c.get('full_name', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"Passport: {c.get('passport_number', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"Contact: {c.get('phone', '')} | {c.get('email', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"Address: {c.get('address', '')}"); y -= 8 * mm
    else:
        c_canvas.drawString(20 * mm, y, "Customer: N/A"); y -= 8 * mm

    # Vehicle Details
    c_canvas.setFont("Helvetica-Bold", 12)
    c_canvas.drawString(20 * mm, y, "Vehicle Details")
    y -= 6 * mm
    c_canvas.setFont("Helvetica", 11)
    c_canvas.drawString(20 * mm, y, f"Brand/Model: {v.get('brand')} {v.get('model')} {v.get('variant', '')}"); y -= 6 * mm
    c_canvas.drawString(20 * mm, y, f"VIN: {v.get('vin')}"); y -= 6 * mm
    c_canvas.drawString(20 * mm, y, f"Purchase Date: {v.get('purchase_date')}"); y -= 8 * mm

    # Shipping Details
    c_canvas.setFont("Helvetica-Bold", 12)
    c_canvas.drawString(20 * mm, y, "Shipping Details")
    y -= 6 * mm
    c_canvas.setFont("Helvetica", 11)
    if s:
        c_canvas.drawString(20 * mm, y, f"Container: {s.get('container_number', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"Company: {s.get('shipping_company', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"ETA: {s.get('estimated_arrival', '')}"); y -= 6 * mm
        c_canvas.drawString(20 * mm, y, f"Status: {s.get('status', '')}"); y -= 8 * mm
    else:
        c_canvas.drawString(20 * mm, y, "No shipping record"); y -= 8 * mm

    # Payment Summary
    c_canvas.setFont("Helvetica-Bold", 12)
    c_canvas.drawString(20 * mm, y, "Payment Summary")
    y -= 6 * mm
    c_canvas.setFont("Helvetica", 11)
    if payments:
        total = sum([p.get("amount", 0) for p in payments])
        c_canvas.drawString(20 * mm, y, f"Payments: {len(payments)} | Total Paid: ${total:,.2f}"); y -= 6 * mm
        for p in payments[:10]:
            c_canvas.drawString(25 * mm, y, f"{p.get('payment_date')} - {p.get('payment_type')} - {p.get('payment_status')} - ${p.get('amount')}")
            y -= 6 * mm
    else:
        c_canvas.drawString(20 * mm, y, "No payments recorded"); y -= 6 * mm

    # Footer
    c_canvas.setFont("Helvetica", 9)
    c_canvas.drawString(20 * mm, 15 * mm, "Thank you for choosing Pablo's Car")

    c_canvas.showPage()
    c_canvas.save()
    bio.seek(0)
    return bio


def send_email_with_attachment(to_email: str, subject: str, body: str, filename: str, file_stream: BytesIO):
    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    password = os.getenv("SMTP_PASS")
    sender = os.getenv("SMTP_FROM", user or "no-reply@pabloscar.com")
    if not host:
        raise HTTPException(status_code=500, detail="SMTP not configured")

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = to_email
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    part = MIMEBase('application', "octet-stream")
    part.set_payload(file_stream.read())
    encoders.encode_base64(part)
    part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
    msg.attach(part)

    with smtplib.SMTP(host, port) as server:
        server.starttls()
        if user and password:
            server.login(user, password)
        server.sendmail(sender, [to_email], msg.as_string())


@app.get("/shipping-sheet/{vehicle_id}")
def shipping_sheet(vehicle_id: str, fmt: Literal["pdf", "xlsx"] = "pdf", email_to: Optional[EmailStr] = None, current=Depends(get_current_user)):
    ensure_db()
    if fmt == "pdf":
        pdf_stream = build_shipping_sheet_pdf(vehicle_id)
        filename = f"shipping_sheet_{vehicle_id}.pdf"
        if email_to:
            data_bytes = pdf_stream.getvalue()
            send_email_with_attachment(email_to, "Shipping Sheet", "Please find attached shipping sheet.", filename, BytesIO(data_bytes))
            pdf_stream = BytesIO(data_bytes)
        return StreamingResponse(pdf_stream, media_type="application/pdf", headers={"Content-Disposition": f"attachment; filename={filename}"})

    # Excel version
    wb = Workbook()
    ws = wb.active
    ws.title = "Shipping Sheet"

    v = db["vehicle"].find_one({"_id": oid(vehicle_id)})
    s = db["shipping"].find_one({"vehicle_id": vehicle_id})
    c = None
    if v:
        cid = v.get("customer_id")
        if cid:
            try:
                c = db["customer"].find_one({"_id": oid(cid)})
            except HTTPException:
                c = None

    ws.append(["Pablo's Car - Shipping Sheet"])  # Title
    ws.append([""])
    ws.append(["Customer", c.get("full_name") if c else "N/A"])
    ws.append(["Passport", c.get("passport_number") if c else "N/A"])
    ws.append(["Contact", f"{c.get('phone', '')} {c.get('email', '')}" if c else "N/A"])
    ws.append([""])
    if v:
        ws.append(["Vehicle", f"{v.get('brand')} {v.get('model')} {v.get('variant', '')}"])
        ws.append(["VIN", v.get("vin")])
        ws.append(["Purchase Date", str(v.get("purchase_date"))])
    ws.append([""])
    if s:
        ws.append(["Container", s.get("container_number")])
        ws.append(["Company", s.get("shipping_company")])
        ws.append(["ETA", str(s.get("estimated_arrival"))])
        ws.append(["Status", s.get("status")])

    bio = BytesIO()
    wb.save(bio)
    bio.seek(0)
    filename = f"shipping_sheet_{vehicle_id}.xlsx"
    if email_to:
        data_bytes = bio.getvalue()
        send_email_with_attachment(email_to, "Shipping Sheet", "Please find attached shipping sheet.", filename, BytesIO(data_bytes))
        bio = BytesIO(data_bytes)
    return StreamingResponse(bio, media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", headers={"Content-Disposition": f"attachment; filename={filename}"})


@app.get("/")
def root():
    return {"message": "Pablo's Car API running"}


@app.get("/test")
def test():
    status = {
        "backend": "running",
        "database": "connected" if db is not None else "not_configured",
    }
    if db is not None:
        try:
            status["collections"] = db.list_collection_names()
        except Exception as e:
            status["error"] = str(e)
    return status


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run(app, host="0.0.0.0", port=port)
