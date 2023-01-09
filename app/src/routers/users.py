from fastapi import APIRouter, Depends, HTTPException, status

from sqlalchemy.orm import Session

from ..core.auth import oauth2_scheme, authenticate_user
from ..crud import users
from ..schemas.users import User, UserCreate, UserUpdate
from ..database.db_config import get_db

router = APIRouter(tags=['users'])


@router.post("/api/user/", response_model=User, status_code=200)
async def create_user(user: UserCreate,
                      db: Session = Depends(get_db),
                      token: str = Depends(oauth2_scheme)):
    db_user = users.get_user(db, user.username)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User already exists")
    return users.create_user(db, user)


@router.get("/api/user/{username}")
async def get_one_user(username: str,
                       db: Session = Depends(get_db),
                       token: str = Depends(oauth2_scheme)):
    user = users.get_user(db, username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User not found")
    return user


@router.put("/api/user/", status_code=status.HTTP_200_OK)
async def update_user_password(user: UserUpdate,
                               db: Session = Depends(get_db),
                               token: str = Depends(oauth2_scheme)):
    not_found_exception = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                        detail="User not found")

    authenticated = authenticate_user(db, user.username, user.old_password)
    if not authenticated:
        raise not_found_exception

    user = users.update_user_password(db, user)
    if user is None:
        raise not_found_exception

    return {"detail": "password successfully changed"}


@router.delete("/api/user/", status_code=status.HTTP_200_OK)
async def delete_user(user: UserCreate,
                      db: Session = Depends(get_db),
                      token: str = Depends(oauth2_scheme)):
    not_found_exception = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                        detail="User not found")

    authenticated = authenticate_user(db, user.username, user.old_password)
    if not authenticated:
        raise not_found_exception

    user = users.get_user(db, user.username)
    if not user:
        raise not_found_exception

    users.delete_user(db, user.username)
    return {"detail": "user successfully deleted"}
