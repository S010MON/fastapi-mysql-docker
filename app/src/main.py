from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware

from .routers import auth, users
from .crud import users as crud_users
from .database import models
from .database.db_config import engine, SessionLocal
from .schemas.users import UserCreate


models.Base.metadata.create_all(bind=engine)

# Build REST API
app = FastAPI()
app.include_router(auth.router)
app.include_router(users.router)


origins = [
    "http://localhost.example.com",
    "https://localhost.example.com",
    "http://localhost",
    "http://localhost:8080",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    root_user = UserCreate(username="root",
                           password="password")
    db = SessionLocal()
    crud_users.create_user(db, root_user)
    db.close()


@app.get("/", status_code=status.HTTP_418_IM_A_TEAPOT)
async def root(request: Request):
    return {"description": "I am a teapot"}
