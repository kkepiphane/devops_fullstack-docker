# backend/app/api/v1/auth.py
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def auth_root():
    return {"message": "Auth endpoints"}