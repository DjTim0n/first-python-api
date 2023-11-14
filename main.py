from fastapi import FastAPI, HTTPException, Depends, status
from pydantic import BaseModel
from motor.motor_asyncio import AsyncIOMotorClient
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional
from fastapi.middleware.cors import CORSMiddleware
import asyncio
from bson.objectid import ObjectId
import random
import string
from smtplib import SMTP
from email.message import EmailMessage

app = FastAPI()


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

def generate_password(length=8):
    characters = string.ascii_letters + string.digits + string.punctuation
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

async def testfunction():
    while True:
        # Вызываем функцию с задержкой в 24 часа
        await asyncio.sleep(60 * 60)
        print("Success")
        async for user in users_collection.find({}):
            id = user.get("_id")
            if id:  
              generated_pass = generate_password()
              email_alert("У вас сменился пароль", generated_pass, user.get("email"))
              users_collection.update_one(
                {"_id": ObjectId(id)},
                {"$set": {"hashed_password": pwd_context.hash(generated_pass)}}
							)

def startup_event(): 
    asyncio.create_task(testfunction())

app.on_event("startup")(startup_event)
# Настройка CORS политики

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Настройки для MongoDB
MONGO_DB_URL = "mongodb+srv://djtimon100:2005200ba@cluster0.uaks0oj.mongodb.net/"  # Замените на ваш URL MongoDB
MONGO_DB_NAME = "testdatabase"  # Замените на вашу базу данных

# Создаем подключение к MongoDB
client = AsyncIOMotorClient(MONGO_DB_URL)
db = client[MONGO_DB_NAME]

# Класс модели пользователя
class User(BaseModel):
    email: str

# Класс модели для хранения пароля
class UserInDB(User):
    hashed_password: str

# Класс модели для создания пользователя
class UserCreate(User):
    password: str


# Класс модели для генерации токена
class Token(BaseModel):
    access_token: str
    token_type: str

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

# Создаем коллекцию для пользователей в MongoDB
users_collection = db["users"]

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
    result = await users_collection.insert_one(user_in_db.dict())
    
    return user

# Аутентификация пользователя и выдача токена
@app.post("/login", response_model=Token)
async def login(user: UserCreate):
    # Ищем пользователя по имени
    user_in_db = await users_collection.find_one({"email": user.email})
    if not user_in_db or not pwd_context.verify(user.password, user_in_db["hashed_password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    # Генерируем токен
    access_token_expires = timedelta(minutes=15)
    access_token = create_access_token(data={"sub": user.email}, expires_delta=access_token_expires)
    
    return {"access_token": access_token, "token_type": "bearer"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
