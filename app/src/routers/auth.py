from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm

from sqlalchemy.orm import Session

from ..core import auth
from ..crud import users
from ..database.db_config import get_db

router = APIRouter(tags=['auth'])


@router.post("/api/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends(),
                db: Session = Depends(get_db)):
    authenticated = auth.authenticate_user(db, form_data.username, form_data.password)

    if not authenticated:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Incorrect username or password",
                            headers={"WWW-Authenticate": "Bearer"})

    user = users.get_user(db, form_data.username)
    access_token = auth.create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}
