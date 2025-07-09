# auth.py
from datetime import datetime, timedelta
from jose import jwt, JWTError

ACCESS_SECRET = "Oy2DKLPzKMvYg2yIFKFFnAqz9c7r9d4zqHTjW_Z4iGM"
REFRESH_SECRET = "q1tcIkK9PiO0T4wPKnku6n0cMl8-ZH_vTWObi1W_QQPRDzkJ2_LDYxgzkxShY9ZrJ"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, ACCESS_SECRET, algorithm=ALGORITHM)

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, REFRESH_SECRET, algorithm=ALGORITHM)

def verify_token(token: str, refresh=False):
    key = REFRESH_SECRET if refresh else ACCESS_SECRET
    try:
        payload = jwt.decode(token, key, algorithms=[ALGORITHM])
        return payload
    except JWTError:
        return None
