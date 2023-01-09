from fastapi import FastAPI, Request, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm

from jose import JWTError

from sqlalchemy.orm import Session

from .core import auth
from .crud import users
from .schemas.users import User, UserCreate
from .schemas.tokens import TokenData
from .database.db_config import engine, SessionLocal, get_db
from .database import models

models.Base.metadata.create_all(bind=engine)

# Build REST API
app = FastAPI()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/token")


@app.on_event("startup")
async def startup_event():
    root_user = UserCreate(username="root",
                           password="password")
    db = SessionLocal()
    users.create_user(db, root_user)
    db.close()


@app.get("/", status_code=status.HTTP_200_OK)
async def root(request: Request):
    return {"msg": "hello world"}


@app.post("/api/user/", response_model=User, status_code=200)
async def create_user(user: UserCreate, db: Session = Depends(get_db)):
    db_user = users.get_user(db, user.username)
    if db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User already exists")
    return users.create_user(db, user)


@app.get("/api/user/{username}")
async def get_one_user(username: str,
                       db: Session = Depends(get_db),
                       token: str = Depends(oauth2_scheme)):
    user = users.get_user(db, username)
    if user is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="User not found")
    return user


@app.put("/api/user/{username}", status_code=status.HTTP_200_OK)
async def update_user(username: str, token: str = Depends(oauth2_scheme)):
    raise HTTPException(status_code=status.HTTP_501_NOT_IMPLEMENTED,
                        detail="not implemented")


@app.delete("/api/user/{username}", status_code=status.HTTP_200_OK)
async def delete_user(username: str,
                      db: Session = Depends(get_db),
                      token: str = Depends(oauth2_scheme)):
    user = users.get_user(db, username)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,
                            detail="user not found")

    users.delete_user(db, username)
    return {"detail": "user deleted"}


@app.post("/api/token")
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


async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = auth.decode(token)
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = auth.get_user(token_data.username)
    if user is None:
        raise credentials_exception
    return user
