from fastapi import APIRouter, Depends, HTTPException, status

from sqlalchemy.orm import Session

from ..core.auth import oauth2_scheme, authenticate_user, get_current_active_user
from ..crud import users
from ..schemas.users import User, UserCreate, UserUpdate
from ..database.db_config import get_db

router = APIRouter(tags=['users'])

NOT_FOUND_EXCEPTION = HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="User not found")


@router.get("/api/user/whoami", response_model=User, status_code=200)
async def who_am_i(current_user: User = Depends(get_current_active_user)):
    return current_user


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
        raise NOT_FOUND_EXCEPTION
    return user


@router.put("/api/user/", status_code=status.HTTP_200_OK)
async def update_user_password(user: UserUpdate,
                               db: Session = Depends(get_db),
                               token: str = Depends(oauth2_scheme)):
    authenticate_user(db, user.username, user.old_password)

    user = users.update_user_password(db, user)
    if user is None:
        raise NOT_FOUND_EXCEPTION

    return {"detail": "password successfully changed"}


@router.delete("/api/user/", status_code=status.HTTP_200_OK)
async def delete_current_user(user: User = Depends(get_current_active_user),
                              db: Session = Depends(oauth2_scheme)):
    users.delete_user(db, user.username)
    return {"detail": "user successfully deleted"}
