# backend/app/api/v1/users.py
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
def users_root():
    return {"message": "Users endpoints"}