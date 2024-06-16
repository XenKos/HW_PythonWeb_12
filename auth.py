import jwt
from datetime import datetime, timedelta
from fastapi import HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from sqlalchemy.orm import Session
from . import crud, database
from .config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES, REFRESH_TOKEN_EXPIRE_DAYS
from .schemas import TokenData, UserCreate

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(token: str, credentials_exception):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    return token_data

def register_user(user: UserCreate, db: Session):
    existing_user = crud.get_user_by_email(db, email=user.email)
    if existing_user:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Електронна адреса вже зареєстрована")
    
    new_user = crud.create_user(db=db, user=user)
    
    return new_user

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(database.get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Не вдалося підтвердити авторизацію",
        headers={"WWW-Authenticate": "Bearer"},
    )
    payload = verify_token(token, credentials_exception)
    user = crud.get_user_by_email(db, email=payload.email)
    if user is None:
        raise credentials_exception
    return user

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

def authenticate_user(email: str, password: str, db: Session):
    user = crud.authenticate_user(db, email, password)
    if not user or not crud.verify_password(password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Неправильна електронна адреса чи пароль")
    return user
