from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware 
from fastapi.responses import RedirectResponse
import random
from smtplib import SMTP
from email.message import EmailMessage
import asyncio
import uvicorn
app = FastAPI()

origins = ["*"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройки для MongoDB
MONGO_DB_URL = "mongodb+srv://djtimon100:2005200ba@cluster0.uaks0oj.mongodb.net/"  
MONGO_DB_NAME = "VladTestDataBase"

# Создаем подключение к MongoDB
client = AsyncIOMotorClient(MONGO_DB_URL)
db = client[MONGO_DB_NAME]

# Создаем коллекцию для пользователей в MongoDB
users_collection = db["users"]
verify_collection = db["verify_users"]


# Секретный ключ для генерации и валидации токена
SECRET_KEY = "TIMURTIMURTIMUR"
ALGORITHM = "HS256"

# Контекст для хэширования паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Генерация токена
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def email_alert(subject, body, to):
    msg = EmailMessage()
    msg.set_content(body)

    msg['subject'] = subject
    msg['to'] = to

    user = "testemailfordev1@gmail.com"
    password = "fxbtkryvevzerdyv"

    server = SMTP("smtp.gmail.com", 25, timeout=10000)
    server.starttls()
    server.login(user, password)
    server.send_message(msg)

    server.quit()

# Модели 
class User(BaseModel):
    email: str

class UserVerify(User):
    verify_code: int

class UserInDB(User):
    hashed_password: str
    verify: bool = False
    firstName: str = ""
    lastName: str = ""

class UserCreate(User):
    password: str
    firstName: str = ""
    lastName: str = ""

class Token(BaseModel):
    access_token: str
    token_type: str

# Точки:

@app.get("/swagger")
async def swagger():
    return RedirectResponse("/docs")

@app.get("/")
async def test(): 
    return {"detail": "Hello World"}

# Регистрация пользователя
@app.post("/register", response_model=User)
async def register(user: UserCreate):
    # Проверяем, существует ли пользователь с таким же именем
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    
    # Хэшируем пароль
    hashed_password = pwd_context.hash(user.password)
    
    # Создаем пользователя в базе данных
    user_in_db = UserInDB(**user.dict(), hashed_password=hashed_password)
    await users_collection.insert_one(user_in_db.dict())
    
    verify_code = random.randint(100000, 999999)

    email_alert("Код подтвержение", f"{verify_code}", user.email)

    user_verify_in_db = UserVerify(**user.dict(), verify_code=verify_code)
    await verify_collection.insert_one(user_verify_in_db.dict())

    return user

@app.post("/verify_user", response_model=Token)
async def verify_user(user: UserVerify):
    user_in_db: UserVerify = await verify_collection.find_one({"email": user.email}) 
    print(user_in_db)
    if not user_in_db:
        raise HTTPException(status_code=400, detail="Invalid email")
    
    if not user_in_db.get("verify_code"):
        raise HTTPException(status_code=999, detail="Я не нашёл сука")

    if user.verify_code != user_in_db.get("verify_code"):
        raise HTTPException(status_code=400, detail="Invalid code")
    
    await verify_collection.delete_one({"email": user.email})
    await users_collection.update_one(
                {"email": user.email},
                {"$set": {"verify": True}})

    # Генерируем токен
    access_token_expires = timedelta(hours=6)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)

    return {"access_token": access_token, "token_type": "bearer"}

    
# Аутентификация пользователя и выдача токена
@app.post("/login", response_model=Token)
async def login(user: UserCreate):
    # Ищем пользователя по имени
    user_in_db = await users_collection.find_one({"email": user.email})
    if not user_in_db or not pwd_context.verify(user.password, user_in_db["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    if user_in_db.get("verify") == False:
        raise HTTPException(status_code=400, detail="Not verify")

    # Генерируем токен
    access_token_expires = timedelta(minutes=15)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

if __name__ == "__main__":
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
