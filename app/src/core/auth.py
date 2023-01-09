from passlib.context import CryptContext
from jose import jwt
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from ..crud import users
from .config import settings


pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def verify_password(plain_pwd: str, hashed_pwd: str) -> bool:
    return pwd_context.verify(plain_pwd, hashed_pwd)


def hash_password(plain_pwd: str) -> str:
    return pwd_context.hash(plain_pwd)


def decode(token):
    return jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])


def authenticate_user(db: Session, username: str, password: str) -> bool:
    """
    :param db: The database session
    :param username: the user's unique email identifier
    :param password: the plaintext password from the user
    :return: False if the user is not authenticated, the User object if the user is verified
    """
    user = users.get_user(db, username)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return True


def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINS)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt