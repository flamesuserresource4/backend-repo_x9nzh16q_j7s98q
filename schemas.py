"""
Database Schemas for Pablo's Car - Sub-Customer Management System

Each Pydantic model corresponds to a MongoDB collection (class name lowercased).
"""

from pydantic import BaseModel, Field, EmailStr
from typing import Optional, Literal
from datetime import date, datetime

# Authentication models
class User(BaseModel):
    email: EmailStr
    hashed_password: str
    role: Literal["admin", "staff"] = "staff"
    full_name: Optional[str] = None
    is_active: bool = True

# Core domain models
class Customer(BaseModel):
    full_name: str
    passport_number: str
    dob: Optional[date] = None
    address: Optional[str] = None
    phone: Optional[str] = None
    email: Optional[EmailStr] = None

class Vehicle(BaseModel):
    customer_id: str = Field(..., description="Reference to customer _id as string")
    brand: str
    model: str
    variant: Optional[str] = None
    vin: str
    purchase_date: Optional[date] = None
    price: Optional[float] = None
    payment_status: Literal["pending", "partial", "completed"] = "pending"

class Payment(BaseModel):
    customer_id: str
    amount: float
    payment_type: Literal["advance", "final", "other"] = "advance"
    payment_status: Literal["pending", "completed", "failed"] = "pending"
    payment_date: Optional[date] = None

class Shipping(BaseModel):
    vehicle_id: str
    container_number: Optional[str] = None
    shipping_company: Optional[str] = None
    estimated_arrival: Optional[date] = None
    status: Literal["pending", "shipped", "delivered"] = "pending"

# Response helpers
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class LoginRequest(BaseModel):
    email: EmailStr
    password: str
