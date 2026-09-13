from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordRequestForm
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from pydantic import BaseModel, EmailStr
from typing import Optional
from uuid import UUID


from app.db.session import get_db
from app.models.user import User, UserRole
from app.core.auth import (
    verify_password, get_password_hash,
    create_access_token, create_refresh_token, decode_token, get_current_user
)

router = APIRouter(prefix="/auth", tags=["auth"])


class RegisterRequest(BaseModel):
    name: str
    email: EmailStr
    password: str
    role: UserRole = UserRole.analyst


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    user_id: str
    name: str
    email: str
    role: str


async def get_login_form(request: Request) -> Optional[OAuth2PasswordRequestForm]:
    content_type = request.headers.get("content-type", "")
    if "application/x-www-form-urlencoded" in content_type or "multipart/form-data" in content_type:
        try:
            form_data = await request.form()
            username = form_data.get("username")
            password = form_data.get("password")
            if username and password:
                return OAuth2PasswordRequestForm(username=str(username), password=str(password))
        except Exception:
            pass
    return None


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(req: RegisterRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == req.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    user = User(
        name=req.name,
        email=req.email,
        password_hash=get_password_hash(req.password),
        role=req.role,
    )
    db.add(user)
    await db.flush()

    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id), user.role.value),
        user_id=str(user.id),
        name=user.name,
        email=user.email,
        role=user.role.value,
    )


class LoginRequest(BaseModel):
    username: Optional[str] = None
    email: Optional[str] = None
    password: str


@router.post("/login", response_model=TokenResponse)
async def login(
    req: Optional[LoginRequest] = None,
    form: Optional[OAuth2PasswordRequestForm] = Depends(get_login_form),
    db: AsyncSession = Depends(get_db),
):
    # Support both JSON body and form-data
    email_or_user = None
    password = None

    if req and (req.email or req.username):
        email_or_user = req.email or req.username
        password = req.password
    elif form:
        email_or_user = form.username
        password = form.password

    if not email_or_user or not password:
        raise HTTPException(status_code=400, detail="Missing username/email or password")

    result = await db.execute(select(User).where(User.email == email_or_user))
    user = result.scalar_one_or_none()
    if not user or not verify_password(password, user.password_hash):
        raise HTTPException(status_code=401, detail="Incorrect email or password")
    if not user.is_active:
        raise HTTPException(status_code=403, detail="Account is disabled")

    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id), user.role.value),
        user_id=str(user.id),
        name=user.name,
        email=user.email,
        role=user.role.value,
    )



class RefreshRequest(BaseModel):
    refresh_token: str


@router.post("/refresh", response_model=TokenResponse)
async def refresh(req: RefreshRequest, db: AsyncSession = Depends(get_db)):
    payload = decode_token(req.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id = payload.get("sub")
    result = await db.execute(select(User).where(User.id == UUID(user_id)))
    user = result.scalar_one_or_none()
    if not user or not user.is_active:
        raise HTTPException(status_code=401, detail="User not found or disabled")

    return TokenResponse(
        access_token=create_access_token(str(user.id), user.role.value),
        refresh_token=create_refresh_token(str(user.id), user.role.value),
        user_id=str(user.id),
        name=user.name,
        email=user.email,
        role=user.role.value,
    )


@router.get("/me")
async def me(current_user=Depends(get_current_user), db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.id == UUID(current_user.user_id)))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": str(user.id), "name": user.name, "email": user.email, "role": user.role.value}
