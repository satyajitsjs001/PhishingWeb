import os
from datetime import datetime, timedelta
from typing import Optional
import urllib.parse
import joblib
import requests
from bs4 import BeautifulSoup

from fastapi import FastAPI, Depends, HTTPException, status, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from . import models, schemas, crud
from .database import Base, engine, SessionLocal

# SECURITY CONFIG
SECRET_KEY = "a_very_secret_key_change_me_in_production"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# DATABASE INIT
Base.metadata.create_all(bind=engine)

app = FastAPI(title="PhishGuard - Phishing Detection System")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# GLOBALLY LOAD ML MODEL ONCE
trained_model = None
try:
    model_path = os.path.join(os.path.dirname(__file__), "../models/rf_model.pkl")
    trained_model = joblib.load(model_path)
    print("Pre-trained Random Forest model loaded successfully.")
except Exception as e:
    print(f"Warning: Could not load ML model at {model_path}. Error: {e}")

# STATIC & TEMPLATES
# Create directories if they don't exist
os.makedirs("app/templates", exist_ok=True)
os.makedirs("app/static", exist_ok=True)

app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")

# DEPENDENCY
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# SECURITY UTILS
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = schemas.TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = crud.get_user_by_email(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_optional_current_user(request: Request, db: Session = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        return None
    token = auth_header.split(" ")[1]
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            return None
        return crud.get_user_by_email(db, email=email)
    except JWTError:
        return None

# ROUTES - PAGES
@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})

@app.get("/signup", response_class=HTMLResponse)
async def signup_page(request: Request):
    return templates.TemplateResponse("signup.html", {"request": request})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page(request: Request, db: Session = Depends(get_db)):
    # This page will use JS to fetch history using the token stored in localStorage
    return templates.TemplateResponse("dashboard.html", {"request": request})

# ROUTES - AUTH API
@app.post("/auth/signup", response_model=schemas.UserResponse)
def signup(email: str = Form(...), password: str = Form(...), db: Session = Depends(get_db)):
    db_user = crud.get_user_by_email(db, email=email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    user_in = schemas.UserCreate(email=email, password=get_password_hash(password))
    return crud.create_user(db, user_in)

@app.post("/auth/token", response_model=schemas.Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = crud.get_user_by_email(db, email=form_data.username)
    if not user or not verify_password(form_data.password, user.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.email}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

# ROUTES - PHISHING API
@app.post("/predict")
async def predict_url(payload: schemas.URLRequest, db: Session = Depends(get_db), current_user: Optional[models.User] = Depends(get_optional_current_user)):
    url = payload.url
    def extract_url_features(url_str):
        parsed = urllib.parse.urlparse(url_str)
        hostname = parsed.netloc

        return [
            len(url_str),                         
            url_str.count('.'),                   
            url_str.count('-'),                   
            url_str.count('@'),                   
            url_str.count('?'),                   
            url_str.count('='),                   
            url_str.count('//'),                  
            url_str.count('https'),               
            len(hostname),                    
            hostname.count('.')               
        ]

    def extract_html_features(url_str, use_html=False):
        if not use_html:
            return [0, 0, 0, 0]
        try:
            response = requests.get(url_str, timeout=5)
            soup = BeautifulSoup(response.text, "html.parser")
            return [
                len(soup.find_all('form')),
                len(soup.find_all('iframe')),
                len(soup.find_all('script')),
                len(soup.find_all('a'))
            ]
        except:
            return [0, 0, 0, 0]

    def extract_features(url_str, use_html=False):
        return extract_url_features(url_str) + extract_html_features(url_str, use_html)

    if trained_model is None:
        return {"url": url, "result": "Error Loading ML Model", "confidence": 0}

    features = extract_features(url)
    try:
        prediction = trained_model.predict([features])[0]
        probabilities = trained_model.predict_proba([features])[0]
        confidence = probabilities[prediction]
    except Exception as e:
        print(f"Prediction Error: {e}")
        prediction = 1 # assume phishing if prediction fails for safety
        confidence = 0.99

    result = "Phishing" if prediction == 1 else "Safe"
        
    # If user is logged in, save to history
    if current_user:
        history_in = schemas.HistoryCreate(url=url, result=result, confidence=float(confidence))
        crud.create_history(db, history_in, user_id=current_user.id)
    
    # Return formatted confidence to two decimal places
    return {"url": url, "result": result, "confidence": round(float(confidence), 2)}

@app.get("/statistics", response_model=schemas.StatisticsResponse)
async def get_system_statistics(db: Session = Depends(get_db), current_user: Optional[models.User] = Depends(get_optional_current_user)):
    stats = crud.get_platform_statistics(db)
    
    if current_user:
        user_stats = crud.get_user_statistics(db, user_id=current_user.id)
        stats.update(user_stats)
        
    return stats

@app.get("/history", response_model=list[schemas.HistoryResponse])
async def read_history(db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    return crud.get_user_history(db, user_id=current_user.id)

@app.delete("/history/{history_id}")
async def delete_history(history_id: int, db: Session = Depends(get_db), current_user: models.User = Depends(get_current_user)):
    deleted = crud.delete_history_item(db, history_id=history_id, user_id=current_user.id)
    if not deleted:
        raise HTTPException(status_code=404, detail="History item not found")
    return {"message": "History item deleted"}