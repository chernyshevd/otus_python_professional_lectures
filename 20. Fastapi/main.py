from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from typing import List
from passlib.context import CryptContext

app = FastAPI()

# Настройка схемы аутентификации
security = HTTPBasic()

#жэширование паролей
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

#имитация базы данных пользователей
fake_users_db = {
    "john_doe": {
        "username": "john_doe",
        "hashed_password": pwd_context.hash("secret"),
        "email": "john@gmail.de",
        "age": 25
    }
}

#создаем pydantic модель
class User(BaseModel):
    username: str
    email: str
    age: int

#функция для проверки пользователя
def authentificate_user(credentials: HTTPBasicCredentials):
    user = fake_users_db.get(credentials.username)
    if user is None or not pwd_context.verify(credentials.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="incorrect username or password",
            headers={"WWW-Authenticate": "Basic"}
        )
    return user

@app.get("/users/me",response_model=User)
def read_current_user(credentials: HTTPBasicCredentials = Depends(security)):
    return authentificate_user(credentials)

@app.post("/users/",response_model=User)
def create_user(user:User):
    #создаем нового пользователя с хэшированием пароля
    hashed_password = pwd_context.hash("secret") # можно заменить на настощий пароль
    user_data = user.dict()
    user_data["hashed_password"] = hashed_password
    fake_users_db[user.username] = user_data
    return user
