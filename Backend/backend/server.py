from fastapi import FastAPI, APIRouter, HTTPException, Depends, Request
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
import asyncio
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict, EmailStr
from typing import List, Optional, Dict
import uuid
from datetime import datetime, timezone, timedelta
import jwt
from passlib.context import CryptContext
import resend

# Stripe integration
from emergentintegrations.payments.stripe.checkout import (
    StripeCheckout, 
    CheckoutSessionResponse, 
    CheckoutStatusResponse, 
    CheckoutSessionRequest
)

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')

# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]

# JWT Configuration
JWT_SECRET = os.environ.get('JWT_SECRET', 'invoica-secret-key-change-in-production')
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_HOURS = 24

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Resend configuration
resend.api_key = os.environ.get('RESEND_API_KEY', '')
SENDER_EMAIL = os.environ.get('SENDER_EMAIL', 'onboarding@resend.dev')
CONTACT_EMAIL = os.environ.get('CONTACT_EMAIL', 'hello@invoica.co.uk')

# Stripe configuration
STRIPE_API_KEY = os.environ.get('STRIPE_API_KEY', 'sk_test_emergent')

# Create the main app
app = FastAPI(title="Invoica API")

# Create routers
api_router = APIRouter(prefix="/api")
auth_router = APIRouter(prefix="/api/auth", tags=["Authentication"])
payment_router = APIRouter(prefix="/api/payments", tags=["Payments"])
contact_router = APIRouter(prefix="/api/contact", tags=["Contact"])
blog_router = APIRouter(prefix="/api/blog", tags=["Blog"])

# Security
security = HTTPBearer(auto_error=False)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==================== MODELS ====================

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    name: str
    email: str
    created_at: str
    subscription_status: str = "trial"

class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

class ContactForm(BaseModel):
    name: str
    email: EmailStr
    subject: str
    message: str

class ContactResponse(BaseModel):
    success: bool
    message: str

class BlogPost(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    title: str
    slug: str
    excerpt: str
    content: str
    author: str
    category: str
    image_url: str
    published_at: str
    read_time: str

class PaymentTransaction(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str
    session_id: str
    user_id: Optional[str] = None
    email: Optional[str] = None
    amount: float
    currency: str
    status: str
    payment_status: str
    metadata: Dict = {}
    created_at: str
    updated_at: str

class CheckoutRequest(BaseModel):
    origin_url: str
    user_email: Optional[str] = None

class CheckoutResponse(BaseModel):
    url: str
    session_id: str

# ==================== AUTH HELPERS ====================

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def create_access_token(user_id: str, email: str) -> str:
    expire = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRATION_HOURS)
    payload = {
        "sub": user_id,
        "email": email,
        "exp": expire
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        return None
    try:
        payload = jwt.decode(credentials.credentials, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        user_id = payload.get("sub")
        if not user_id:
            return None
        user = await db.users.find_one({"id": user_id}, {"_id": 0})
        return user
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        return None

# ==================== AUTH ROUTES ====================

@auth_router.post("/register", response_model=TokenResponse)
async def register(user_data: UserCreate):
    # Check if user exists
    existing_user = await db.users.find_one({"email": user_data.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Create user
    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    
    user_doc = {
        "id": user_id,
        "name": user_data.name,
        "email": user_data.email,
        "password_hash": hash_password(user_data.password),
        "created_at": now,
        "subscription_status": "trial",
        "trial_ends_at": (datetime.now(timezone.utc) + timedelta(days=14)).isoformat()
    }
    
    await db.users.insert_one(user_doc)
    
    # Create token
    token = create_access_token(user_id, user_data.email)
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user_id,
            name=user_data.name,
            email=user_data.email,
            created_at=now,
            subscription_status="trial"
        )
    )

@auth_router.post("/login", response_model=TokenResponse)
async def login(credentials: UserLogin):
    user = await db.users.find_one({"email": credentials.email}, {"_id": 0})
    if not user:
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    if not verify_password(credentials.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Invalid email or password")
    
    token = create_access_token(user["id"], user["email"])
    
    return TokenResponse(
        access_token=token,
        user=UserResponse(
            id=user["id"],
            name=user["name"],
            email=user["email"],
            created_at=user["created_at"],
            subscription_status=user.get("subscription_status", "trial")
        )
    )

@auth_router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    if not current_user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return UserResponse(
        id=current_user["id"],
        name=current_user["name"],
        email=current_user["email"],
        created_at=current_user["created_at"],
        subscription_status=current_user.get("subscription_status", "trial")
    )

# ==================== PAYMENT ROUTES ====================

# Fixed subscription package
SUBSCRIPTION_PACKAGE = {
    "id": "professional",
    "name": "Professional Plan",
    "amount": 12.00,  # £12/month
    "currency": "gbp"
}

@payment_router.post("/checkout", response_model=CheckoutResponse)
async def create_checkout(request: CheckoutRequest, http_request: Request):
    try:
        # Build webhook URL
        host_url = str(http_request.base_url).rstrip('/')
        webhook_url = f"{host_url}/api/webhook/stripe"
        
        # Initialize Stripe
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
        
        # Build success/cancel URLs from frontend origin
        origin = request.origin_url.rstrip('/')
        success_url = f"{origin}/payment/success?session_id={{CHECKOUT_SESSION_ID}}"
        cancel_url = f"{origin}/payment/cancel"
        
        # Create checkout session with fixed amount (security: never take amount from frontend)
        checkout_request = CheckoutSessionRequest(
            amount=SUBSCRIPTION_PACKAGE["amount"],
            currency=SUBSCRIPTION_PACKAGE["currency"],
            success_url=success_url,
            cancel_url=cancel_url,
            metadata={
                "package_id": SUBSCRIPTION_PACKAGE["id"],
                "user_email": request.user_email or "anonymous"
            }
        )
        
        session: CheckoutSessionResponse = await stripe_checkout.create_checkout_session(checkout_request)
        
        # Create payment transaction record
        now = datetime.now(timezone.utc).isoformat()
        transaction = {
            "id": str(uuid.uuid4()),
            "session_id": session.session_id,
            "email": request.user_email,
            "amount": SUBSCRIPTION_PACKAGE["amount"],
            "currency": SUBSCRIPTION_PACKAGE["currency"],
            "status": "pending",
            "payment_status": "initiated",
            "metadata": {
                "package_id": SUBSCRIPTION_PACKAGE["id"]
            },
            "created_at": now,
            "updated_at": now
        }
        await db.payment_transactions.insert_one(transaction)
        
        return CheckoutResponse(url=session.url, session_id=session.session_id)
        
    except Exception as e:
        logger.error(f"Checkout error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to create checkout: {str(e)}")

@payment_router.get("/status/{session_id}")
async def get_payment_status(session_id: str, http_request: Request):
    try:
        host_url = str(http_request.base_url).rstrip('/')
        webhook_url = f"{host_url}/api/webhook/stripe"
        
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
        status: CheckoutStatusResponse = await stripe_checkout.get_checkout_status(session_id)
        
        # Update transaction in database
        now = datetime.now(timezone.utc).isoformat()
        
        # Check if already processed to prevent duplicate processing
        existing = await db.payment_transactions.find_one({"session_id": session_id}, {"_id": 0})
        
        if existing and existing.get("payment_status") != "paid":
            await db.payment_transactions.update_one(
                {"session_id": session_id},
                {"$set": {
                    "status": status.status,
                    "payment_status": status.payment_status,
                    "updated_at": now
                }}
            )
            
            # If payment successful, update user subscription
            if status.payment_status == "paid" and existing.get("email"):
                await db.users.update_one(
                    {"email": existing["email"]},
                    {"$set": {
                        "subscription_status": "active",
                        "subscription_started_at": now
                    }}
                )
        
        return {
            "status": status.status,
            "payment_status": status.payment_status,
            "amount_total": status.amount_total,
            "currency": status.currency
        }
        
    except Exception as e:
        logger.error(f"Status check error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Failed to check status: {str(e)}")

@api_router.post("/webhook/stripe")
async def stripe_webhook(request: Request):
    try:
        body = await request.body()
        signature = request.headers.get("Stripe-Signature", "")
        
        host_url = str(request.base_url).rstrip('/')
        webhook_url = f"{host_url}/api/webhook/stripe"
        
        stripe_checkout = StripeCheckout(api_key=STRIPE_API_KEY, webhook_url=webhook_url)
        webhook_response = await stripe_checkout.handle_webhook(body, signature)
        
        logger.info(f"Webhook received: {webhook_response.event_type}")
        
        return {"status": "received"}
    except Exception as e:
        logger.error(f"Webhook error: {str(e)}")
        return {"status": "error", "message": str(e)}

# ==================== CONTACT ROUTES ====================

@contact_router.post("/submit", response_model=ContactResponse)
async def submit_contact_form(form: ContactForm):
    try:
        # Store in database
        contact_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        
        contact_doc = {
            "id": contact_id,
            "name": form.name,
            "email": form.email,
            "subject": form.subject,
            "message": form.message,
            "created_at": now,
            "status": "new"
        }
        await db.contact_submissions.insert_one(contact_doc)
        
        # Try to send email if Resend is configured
        if resend.api_key:
            try:
                html_content = f"""
                <html>
                <body style="font-family: Arial, sans-serif; padding: 20px;">
                    <h2 style="color: #2563EB;">New Contact Form Submission</h2>
                    <p><strong>From:</strong> {form.name} ({form.email})</p>
                    <p><strong>Subject:</strong> {form.subject}</p>
                    <hr style="border: 1px solid #E2E8F0; margin: 20px 0;">
                    <p><strong>Message:</strong></p>
                    <p style="background: #F8FAFC; padding: 15px; border-radius: 8px;">{form.message}</p>
                    <hr style="border: 1px solid #E2E8F0; margin: 20px 0;">
                    <p style="color: #64748B; font-size: 12px;">Sent from Invoica contact form</p>
                </body>
                </html>
                """
                
                params = {
                    "from": SENDER_EMAIL,
                    "to": [CONTACT_EMAIL],
                    "subject": f"[Invoica Contact] {form.subject}",
                    "html": html_content,
                    "reply_to": form.email
                }
                
                await asyncio.to_thread(resend.Emails.send, params)
                logger.info(f"Contact email sent for submission {contact_id}")
            except Exception as email_error:
                logger.warning(f"Failed to send contact email: {email_error}")
        
        return ContactResponse(
            success=True,
            message="Thank you for your message! We'll get back to you within 24 hours."
        )
        
    except Exception as e:
        logger.error(f"Contact form error: {str(e)}")
        raise HTTPException(status_code=500, detail="Failed to submit contact form")

# ==================== BLOG ROUTES ====================

# Sample blog posts (in production, these would come from a CMS)
BLOG_POSTS = [
    {
        "id": "1",
        "title": "5 Tips for Managing Your Freelance Finances",
        "slug": "5-tips-managing-freelance-finances",
        "excerpt": "Starting out as a freelancer? Here are essential tips to keep your finances in order from day one.",
        "content": """
        <p>Managing finances as a freelancer can feel overwhelming, especially when you're just starting out. Unlike traditional employment, you're responsible for everything from invoicing to tax planning.</p>
        
        <h3>1. Separate Business and Personal Finances</h3>
        <p>Open a dedicated business bank account. This makes tracking income and expenses much easier and looks more professional when dealing with clients.</p>
        
        <h3>2. Invoice Promptly and Follow Up</h3>
        <p>Send invoices as soon as work is completed. Set up automatic reminders for overdue payments - most clients simply forget, not avoid paying.</p>
        
        <h3>3. Track Every Expense</h3>
        <p>Keep receipts for everything business-related. Software subscriptions, equipment, even a portion of your home office costs can be deductible.</p>
        
        <h3>4. Set Aside Money for Taxes</h3>
        <p>A good rule of thumb is to save 25-30% of your income for taxes. This prevents nasty surprises when tax season arrives.</p>
        
        <h3>5. Use Accounting Software</h3>
        <p>Tools like Invoica can automate much of your financial management, from invoicing to expense tracking and financial reports.</p>
        """,
        "author": "Sarah Mitchell",
        "category": "Finance Tips",
        "image_url": "https://images.unsplash.com/photo-1554224155-6726b3ff858f?w=800",
        "published_at": "2024-01-15",
        "read_time": "5 min read"
    },
    {
        "id": "2",
        "title": "Understanding VAT for Small Businesses in the UK",
        "slug": "understanding-vat-small-businesses-uk",
        "excerpt": "A comprehensive guide to VAT registration, thresholds, and compliance for UK sole traders.",
        "content": """
        <p>Value Added Tax (VAT) is something every UK business owner needs to understand. Here's what you need to know.</p>
        
        <h3>When Do You Need to Register?</h3>
        <p>You must register for VAT if your taxable turnover exceeds £85,000 in any 12-month period. You can also register voluntarily before reaching this threshold.</p>
        
        <h3>Benefits of Voluntary Registration</h3>
        <p>Registering early can help you reclaim VAT on business purchases and may make your business appear more established to potential clients.</p>
        
        <h3>VAT Schemes for Small Businesses</h3>
        <p>The Flat Rate Scheme and Cash Accounting Scheme can simplify VAT management for smaller businesses. Talk to an accountant about which might suit you.</p>
        
        <h3>Keeping Proper Records</h3>
        <p>HMRC requires you to keep VAT records for at least 6 years. Digital record-keeping through software like Invoica ensures you're always compliant.</p>
        """,
        "author": "James Thompson",
        "category": "Tax & Compliance",
        "image_url": "https://images.unsplash.com/photo-1450101499163-c8848c66ca85?w=800",
        "published_at": "2024-01-10",
        "read_time": "7 min read"
    },
    {
        "id": "3",
        "title": "How to Price Your Services as a Freelancer",
        "slug": "how-to-price-services-freelancer",
        "excerpt": "Setting the right price for your services is crucial. Learn strategies to value your work correctly.",
        "content": """
        <p>One of the biggest challenges freelancers face is pricing their services. Charge too little and you'll burn out; too much and you might lose clients.</p>
        
        <h3>Calculate Your Minimum Rate</h3>
        <p>Start by figuring out your expenses, desired salary, and billable hours. This gives you a baseline that ensures sustainability.</p>
        
        <h3>Research Market Rates</h3>
        <p>Look at what others in your industry and location charge. Platforms like LinkedIn and industry forums can provide insights.</p>
        
        <h3>Value-Based Pricing</h3>
        <p>Consider pricing based on the value you deliver rather than just time spent. A logo that transforms a brand is worth more than the hours it took to create.</p>
        
        <h3>Don't Forget Hidden Costs</h3>
        <p>Factor in software subscriptions, equipment depreciation, professional development, and time spent on admin tasks.</p>
        
        <h3>Review Regularly</h3>
        <p>As you gain experience and build your portfolio, your rates should increase. Review pricing annually at minimum.</p>
        """,
        "author": "Emma Clarke",
        "category": "Business Growth",
        "image_url": "https://images.unsplash.com/photo-1553729459-efe14ef6055d?w=800",
        "published_at": "2024-01-05",
        "read_time": "6 min read"
    }
]

@blog_router.get("/posts", response_model=List[BlogPost])
async def get_blog_posts():
    return BLOG_POSTS

@blog_router.get("/posts/{slug}", response_model=BlogPost)
async def get_blog_post(slug: str):
    for post in BLOG_POSTS:
        if post["slug"] == slug:
            return post
    raise HTTPException(status_code=404, detail="Blog post not found")

# ==================== HEALTH CHECK ====================

@api_router.get("/")
async def root():
    return {"message": "Invoica API", "status": "healthy"}

@api_router.get("/health")
async def health_check():
    return {"status": "healthy", "timestamp": datetime.now(timezone.utc).isoformat()}

# ==================== INCLUDE ROUTERS ====================

app.include_router(api_router)
app.include_router(auth_router)
app.include_router(payment_router)
app.include_router(contact_router)
app.include_router(blog_router)

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
