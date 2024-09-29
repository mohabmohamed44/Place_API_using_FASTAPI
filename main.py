from fastapi import FastAPI, Depends, HTTPException, status, Query
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, ConfigDict
from typing import Optional, List
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
from geopy.distance import geodesic
from sqlalchemy.orm import sessionmaker, declarative_base
from sqlalchemy import Column, Boolean, Float, String, Integer, select, delete, update, ForeignKey
from jose import JWTError, jwt
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
import logging
from dotenv import load_dotenv
import os
from contextlib import asynccontextmanager

# Load environment variables
load_dotenv()

# Set up logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Constants for JWT
SECRET_KEY = os.getenv('SECRET_KEY')
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# SqlAlchemy Setup
SQLALCHEMY_DATABASE_URL = os.getenv('DATABASE_URL')
engine = create_async_engine(SQLALCHEMY_DATABASE_URL, echo=True)
AsyncSessionLocal = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
Base = declarative_base()

# Password hashing setup
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# Dependency
async def get_db():
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()

# Models
class UserModel(Base):
    __tablename__ = 'users'
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

class Place(Base):
    __tablename__ = 'places'
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, index=True)
    description = Column(String, index=True)
    coffee = Column(Boolean, default=False)
    wifi = Column(Boolean, default=False)
    food = Column(Boolean, default=False)
    lat = Column(Float)
    lng = Column(Float)

class Review(Base):
    __tablename__ = 'reviews'
    id = Column(Integer, primary_key=True, index=True)
    place_id = Column(Integer, ForeignKey('places.id'))
    user_id = Column(Integer, ForeignKey('users.id'))
    rating = Column(Integer)
    comment = Column(String)

# Pydantic Models
class PlaceBase(BaseModel):
    name: str
    description: str
    coffee: bool
    wifi: bool
    food: bool
    lat: float
    lng: float

    model_config = ConfigDict(from_attributes=True)

class PlaceCreate(PlaceBase):
    pass

class PlaceOut(PlaceBase):
    id: int

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool

    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

class DeleteResponse(BaseModel):
    ok: bool

class TokenData(BaseModel):
    username: Optional[str] = None

class ReviewCreate(BaseModel):
    place_id: int
    rating: int
    comment: str

class ReviewOut(ReviewCreate):
    id: int
    user_id: int

    model_config = ConfigDict(from_attributes=True)

# Helper functions
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_user(db: AsyncSession, username: str):
    result = await db.execute(select(UserModel).filter(UserModel.username == username))
    return result.scalars().first()

async def authenticate_user(db: AsyncSession, username: str, password: str):
    try:
        user = await get_user(db, username)
        if not user:
            logger.warning(f"User not found: {username}")
            return False
        if not verify_password(password, user.hashed_password):
            logger.warning(f"Incorrect password for user: {username}")
            return False
        return user
    except Exception as e:
        logger.error(f"Error in authenticate_user: {str(e)}")
        return False

async def init_db():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    yield
    # Shutdown
    # Add any cleanup code here if needed

app = FastAPI(lifespan=lifespan)

# Routes
@app.post('/users/', response_model=UserOut)
async def create_user(user: UserCreate, db: AsyncSession = Depends(get_db)):
    try:
        # Check if user already exists
        existing_user = await db.execute(select(UserModel).filter(UserModel.username == user.username))
        if existing_user.scalars().first():
            raise HTTPException(status_code=400, detail="Username already registered")

        # Create new user
        hashed_password = get_password_hash(user.password)
        new_user = UserModel(username=user.username, email=user.email, hashed_password=hashed_password)
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        logger.info(f"User created successfully: {user.username}")
        return UserOut.model_validate(new_user)
    except Exception as e:
        logger.error(f"Error creating user: {str(e)}")
        await db.rollback()
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(),
                                 db: AsyncSession = Depends(get_db)):
    try:
        user = await authenticate_user(db, form_data.username, form_data.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect username or password",
                headers={"WWW-Authenticate": "Bearer"},
            )
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": user.username}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}
    except Exception as e:
        logger.error(f"Error in login_for_access_token: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

async def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = await get_user(db, username=token_data.username)
    if user is None:
        raise credentials_exception
    return user

@app.get('/places/', response_model=List[PlaceOut])
async def read_places(skip: int = 0, limit: int = 10, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Place).offset(skip).limit(limit))
    return result.scalars().all()

@app.post('/places/', response_model=PlaceOut)
async def create_place(place: PlaceCreate, db: AsyncSession = Depends(get_db)):
    db_place = Place(**place.model_dump())
    db.add(db_place)
    await db.commit()
    await db.refresh(db_place)
    return db_place

@app.get('/places/{place_id}', response_model=PlaceOut)
async def read_place(place_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Place).filter(Place.id == place_id))
    place = result.scalars().first()
    if place is None:
        raise HTTPException(status_code=404, detail="Place not found")
    return place

@app.put('/places/{place_id}', response_model=PlaceOut)
async def update_place(place_id: int, place: PlaceCreate, db: AsyncSession = Depends(get_db)):
    stmt = update(Place).where(Place.id == place_id).values(**place.model_dump())
    result = await db.execute(stmt)
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Place not found")
    await db.commit()
    return await read_place(place_id, db)

@app.delete('/places/{place_id}', response_model=DeleteResponse)
async def delete_place(place_id: int, db: AsyncSession = Depends(get_db)):
    stmt = select(Place).where(Place.id == place_id)
    result = await db.execute(stmt)
    place = result.scalar_one_or_none()

    if place is None:
        raise HTTPException(status_code=404, detail="Place not found")

    delete_stmt = delete(Place).where(Place.id == place_id)
    await db.execute(delete_stmt)
    await db.commit()

    return {"ok": True}

@app.get('/places/search/', response_model=List[PlaceOut])
async def search_places(
    query: str = Query(..., min_length=3),
    db: AsyncSession = Depends(get_db)
):
    search = f"%{query}%"
    result = await db.execute(
        select(Place).where(
            (Place.name.ilike(search)) | (Place.description.ilike(search))
        )
    )
    return result.scalars().all()

@app.get('/places/category/', response_model=List[PlaceOut])
async def get_places_by_category(
    coffee: bool = False,
    wifi: bool = False,
    food: bool = False,
    db: AsyncSession = Depends(get_db)
):
    query = select(Place)
    if coffee:
        query = query.where(Place.coffee == True)
    if wifi:
        query = query.where(Place.wifi == True)
    if food:
        query = query.where(Place.food == True)

    result = await db.execute(query)
    return result.scalars().all()

@app.get('/places/nearby/', response_model=List[PlaceOut])
async def get_nearby_places(
    lat: float = Query(...),
    lng: float = Query(...),
    radius: float = Query(default=5.0),  # radius in km
    db: AsyncSession = Depends(get_db)
):
    result = await db.execute(select(Place))
    all_places = result.scalars().all()

    nearby_places = [
        place for place in all_places
        if geodesic((lat, lng), (place.lat, place.lng)).km <= radius
    ]

    return nearby_places

@app.get('/users/me/', response_model=UserOut)
async def get_user_profile(current_user: UserModel = Depends(get_current_user)):
    return current_user

@app.put('/users/me/', response_model=UserOut)
async def update_user_profile(
    user_update: UserCreate,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    current_user.username = user_update.username
    current_user.email = user_update.email
    current_user.hashed_password = get_password_hash(user_update.password)

    await db.commit()
    await db.refresh(current_user)
    return current_user

@app.post('/reviews/', response_model=ReviewOut)
async def create_review(
    review: ReviewCreate,
    current_user: UserModel = Depends(get_current_user),
    db: AsyncSession = Depends(get_db)
):
    try:
        # Check if the place exists
        place = await db.execute(select(Place).where(Place.id == review.place_id))
        if place.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Place not found")

        db_review = Review(**review.model_dump(), user_id=current_user.id)
        db.add(db_review)
        await db.commit()
        await db.refresh(db_review)
        return db_review
    except Exception as e:
        await db.rollback()
        logger.error(f"Error creating review: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.get('/places/{place_id}/reviews/', response_model=List[ReviewOut])
async def get_place_reviews(
    place_id: int,
    db: AsyncSession = Depends(get_db)
):
    try:
        # Check if the place exists
        place = await db.execute(select(Place).where(Place.id == place_id))
        if place.scalar_one_or_none() is None:
            raise HTTPException(status_code=404, detail="Place not found")

        result = await db.execute(select(Review).where(Review.place_id == place_id))
        reviews = result.scalars().all()
        return reviews
    except Exception as e:
        logger.error(f"Error getting place reviews: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Internal Server Error: {str(e)}")

@app.get('/')
async def root():
    return {'message': 'Hello World!'}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8080)