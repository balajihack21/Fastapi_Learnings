from passlib.context import CryptContext
from fastapi import APIRouter, Depends, HTTPException, status,Body
from sqlalchemy.orm import Session
import virtual.models.models as models
import virtual.schemas.schemas as schemas
from virtual.db.database import get_db
from virtual.utils.auth import create_access_token, create_refresh_token ,verify_token
from fastapi.responses import JSONResponse
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from virtual.schemas.schemas import EncryptedPassword
from virtual.utils.encryption import decrypt_symmetric_key, aes_decrypt
from fastapi import Form




router = APIRouter()

# Initialize password context for bcrypt
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(db: Session, email: str, password: str):
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        return False
    if not verify_password(password, user.password):
        return False
    return user


@router.post("/users/", response_model=schemas.UserResponse)
def create_user(
    name: str = Body(...),
    email: str = Body(...),
    encrypted: EncryptedPassword = Body(...),
    db: Session = Depends(get_db)
):
    existing_user = db.query(models.User).filter(models.User.email == email).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Email already registered")

    aes_key = decrypt_symmetric_key(encrypted.encrypted_key)
    plain_password = aes_decrypt(encrypted.encrypted_password, encrypted.iv, aes_key)

    hashed_pwd = hash_password(plain_password)
    db_user = models.User(name=name, email=email, password=hashed_pwd)
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user




@router.post("/login")
def login(
    email: str = Body(...),
    encrypted: EncryptedPassword = Body(...),
    db: Session = Depends(get_db)
):
    aes_key = decrypt_symmetric_key(encrypted.encrypted_key)
    plain_password = aes_decrypt(encrypted.encrypted_password, encrypted.iv, aes_key)

    user = authenticate_user(db, email, plain_password)
    if not user:
        raise HTTPException(status_code=401, detail="Incorrect email or password")

    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}


@router.get("/public-key")
def get_public_key():
    from virtual.utils.encryption import get_public_key_pem
    return {"key": get_public_key_pem()}


@router.post("/refresh")
def refresh_token(refresh_token: str = Body(...), db: Session = Depends(get_db)):
    payload = verify_token(refresh_token, refresh=True)
    if not payload:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    email = payload.get("sub")
    db_user = db.query(models.User).filter(models.User.email == email).first()

    if not db_user or db_user.refresh_token != refresh_token:
        raise HTTPException(status_code=403, detail="Token mismatch or user not found")

    new_access_token = create_access_token({"sub": email})
    return {
        "access_token": new_access_token,
        "token_type": "bearer"
    }



oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> models.User:
    payload = verify_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    email = payload.get("sub")
    if not email:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token payload missing subject",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user = db.query(models.User).filter(models.User.email == email).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    return user

@router.get("/me", response_model=schemas.UserResponse)
def read_me(current_user: models.User = Depends(get_current_user)):
    return current_user


