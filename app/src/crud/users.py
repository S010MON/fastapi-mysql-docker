from sqlalchemy.orm import Session
from app.src.database import models
from app.src.schemas.users import User, UserCreate
from app.src.core import auth


def get_user(db: Session, username: str) -> User:
    return db.query(models.User) \
        .filter(models.User.username == username) \
        .first()


def create_user(db: Session, user: UserCreate):
    hashed_password = auth.hash_password(user.password)
    db_user = models.User(username=user.username,
                          hashed_password=hashed_password,
                          disabled=False)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def delete_user(db: Session, username: str) -> bool:
    user = db.query(models.User)\
        .filter(models.User.username == username)\
        .first()
    if not user:
        return False
    db.delete(user)
    db.commit()
    return True