import os
os.environ["PASSLIB_BCRYPT_BACKEND"] = "builtin"

import uvicorn
import bcrypt
import shutil
import jwt
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional, Annotated

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Enum, DateTime
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from pydantic import BaseModel, ConfigDict

# --- 1. 設定與資料庫 ---

SQLALCHEMY_DATABASE_URL = "sqlite:///./platform.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

UPLOAD_DIRECTORY = "uploads"
Path(UPLOAD_DIRECTORY).mkdir(parents=True, exist_ok=True)

# --- 2. 資料庫模型 (Models) ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum("client", "freelancer", name="user_roles"), nullable=False)

    projects_owned = relationship("Project", foreign_keys="[Project.owner_id]", back_populates="owner")
    projects_assigned = relationship("Project", foreign_keys="[Project.selected_freelancer_id]", back_populates="selected_freelancer")
    bids = relationship("Bid", back_populates="freelancer")
    reviews_received = relationship("Review", foreign_keys="[Review.reviewee_id]", back_populates="reviewee")

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(String)
    status = Column(String, default="open", nullable=False)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    selected_freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    submission_file_url = Column(String, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    owner = relationship("User", foreign_keys=[owner_id], back_populates="projects_owned")
    selected_freelancer = relationship("User", foreign_keys=[selected_freelancer_id], back_populates="projects_assigned")
    bids = relationship("Bid", back_populates="project", cascade="all, delete-orphan")
    reviews = relationship("Review", back_populates="project")

class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    message = Column(String, nullable=True)
    
    project = relationship("Project", back_populates="bids")
    freelancer = relationship("User", back_populates="bids")

class Review(Base):
    __tablename__ = "reviews"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    reviewer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    reviewee_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # 評分維度 (1-5)
    # 若被評者是 Freelancer (乙方): 1=產出品質, 2=執行效率, 3=合作態度
    # 若被評者是 Client (甲方): 1=需求合理性, 2=驗收難度, 3=合作態度
    rating_1 = Column(Integer, nullable=False) 
    rating_2 = Column(Integer, nullable=False)
    rating_3 = Column(Integer, nullable=False)
    
    comment = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="reviews")
    reviewer = relationship("User", foreign_keys=[reviewer_id])
    reviewee = relationship("User", foreign_keys=[reviewee_id], back_populates="reviews_received")

# --- 3. Pydantic Schemas ---

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: str

class UserInDB(UserBase):
    id: int
    role: str
    model_config = ConfigDict(from_attributes=True)

class ReviewCreate(BaseModel):
    rating_1: int
    rating_2: int
    rating_3: int
    comment: Optional[str] = None

class ReviewInDB(ReviewCreate):
    id: int
    reviewer_name: str
    created_at: datetime
    model_config = ConfigDict(from_attributes=True)

class UserStats(BaseModel):
    avg_rating: float
    review_count: int
    reviews: List[ReviewInDB]

class ProjectCreate(BaseModel):
    title: str
    description: Optional[str] = None

class ProjectInDB(ProjectCreate):
    id: int
    owner_id: int
    status: str
    selected_freelancer_id: Optional[int] = None
    submission_file_url: Optional[str] = None
    owner_avg_rating: float = 0.0
    owner_review_count: int = 0
    has_reviewed: bool = False
    model_config = ConfigDict(from_attributes=True)

class BidCreate(BaseModel):
    amount: float
    message: Optional[str] = None

class BidInDB(BidCreate):
    id: int
    freelancer_id: int
    freelancer_name: str
    freelancer_avg_rating: float = 0.0
    freelancer_review_count: int = 0
    model_config = ConfigDict(from_attributes=True)

class Token(BaseModel):
    access_token: str
    token_type: str

# --- 4. 輔助功能 ---

SECRET_KEY = "simple_secret_key"
ALGORITHM = "HS256"

def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

def get_password_hash(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(plain, hashed):
    return bcrypt.checkpw(plain.encode('utf-8'), hashed.encode('utf-8'))

def create_access_token(data: dict):
    to_encode = data.copy()
    to_encode.update({"exp": datetime.now(timezone.utc) + timedelta(minutes=60)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: Annotated[str, Depends(OAuth2PasswordBearer(tokenUrl="token"))], db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.username == payload.get("sub")).first()
        if not user: raise HTTPException(status_code=401, detail="無效憑證")
        return user
    except:
        raise HTTPException(status_code=401, detail="無效憑證")

def calculate_user_stats(user_id: int, db: Session):
    reviews = db.query(Review).filter(Review.reviewee_id == user_id).all()
    count = len(reviews)
    if count == 0: return 0.0, 0
    total = sum([(r.rating_1 + r.rating_2 + r.rating_3) / 3.0 for r in reviews])
    return round(total / count, 1), count

# --- 5. API 路由 ---

app = FastAPI()
Base.metadata.create_all(bind=engine)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIRECTORY), name="uploads")

@app.post("/register")
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="用戶名已存在")
    new_user = User(username=user.username, hashed_password=get_password_hash(user.password), role=user.role)
    db.add(new_user)
    db.commit()
    return {"msg": "註冊成功"}

@app.post("/token", response_model=Token)
def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=400, detail="帳號或密碼錯誤")
    return {"access_token": create_access_token({"sub": user.username}), "token_type": "bearer"}

@app.get("/users/me", response_model=UserInDB)
def read_me(user: User = Depends(get_current_user)):
    return user

@app.get("/users/{user_id}/stats", response_model=UserStats)
def get_user_stats_api(user_id: int, db: Session = Depends(get_db)):
    avg, count = calculate_user_stats(user_id, db)
    reviews = db.query(Review).filter(Review.reviewee_id == user_id).order_by(Review.created_at.desc()).all()
    reviews_out = [ReviewInDB(
        id=r.id, rating_1=r.rating_1, rating_2=r.rating_2, rating_3=r.rating_3,
        comment=r.comment, created_at=r.created_at, reviewer_name=r.reviewer.username
    ) for r in reviews]
    return {"avg_rating": avg, "review_count": count, "reviews": reviews_out}

@app.post("/projects", response_model=ProjectInDB)
def create_project(p: ProjectCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "client": raise HTTPException(403, "僅委託人可建立專案")
    project = Project(**p.model_dump(), owner_id=user.id)
    db.add(project)
    db.commit()
    db.refresh(project)
    return project

@app.get("/projects", response_model=List[ProjectInDB])
def get_open_projects(db: Session = Depends(get_db)):
    projects = db.query(Project).filter(Project.status == "open").all()
    for p in projects:
        p.owner_avg_rating, p.owner_review_count = calculate_user_stats(p.owner_id, db)
    return projects

@app.get("/projects/my", response_model=List[ProjectInDB])
def get_my_projects(db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role == "client":
        projects = db.query(Project).filter(Project.owner_id == user.id).all()
    else:
        projects = db.query(Project).filter(Project.selected_freelancer_id == user.id).all()
    for p in projects:
        p.owner_avg_rating, p.owner_review_count = calculate_user_stats(p.owner_id, db)
        existing = db.query(Review).filter(Review.project_id == p.id, Review.reviewer_id == user.id).first()
        p.has_reviewed = True if existing else False
    return projects

@app.post("/projects/{pid}/bid")
def bid_project(pid: int, bid: BidCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    if user.role != "freelancer": raise HTTPException(403, "僅接案人可投標")
    if db.query(Bid).filter(Bid.project_id == pid, Bid.freelancer_id == user.id).first():
        raise HTTPException(400, "已投標過")
    db.add(Bid(**bid.model_dump(), project_id=pid, freelancer_id=user.id))
    db.commit()
    return {"msg": "投標成功"}

@app.get("/projects/{pid}/bids", response_model=List[BidInDB])
def get_bids(pid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    project = db.query(Project).filter(Project.id == pid).first()
    if not project or project.owner_id != user.id: raise HTTPException(403, "權限不足")
    bids = db.query(Bid).options(joinedload(Bid.freelancer)).filter(Bid.project_id == pid).all()
    result = []
    for b in bids:
        avg, count = calculate_user_stats(b.freelancer_id, db)
        result.append(BidInDB(
            id=b.id, amount=b.amount, message=b.message, freelancer_id=b.freelancer_id,
            freelancer_name=b.freelancer.username, freelancer_avg_rating=avg, freelancer_review_count=count
        ))
    return result

@app.post("/bids/{bid_id}/accept")
def accept_bid(bid_id: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    bid = db.query(Bid).options(joinedload(Bid.project)).filter(Bid.id == bid_id).first()
    if not bid or bid.project.owner_id != user.id: raise HTTPException(403, "權限不足")
    bid.project.status = "in_progress"
    bid.project.selected_freelancer_id = bid.freelancer_id
    db.commit()
    return {"msg": "已接受投標"}

@app.post("/projects/{pid}/submit_file")
def submit_file(pid: int, file: UploadFile = File(...), db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    proj = db.query(Project).filter(Project.id == pid, Project.selected_freelancer_id == user.id).first()
    if not proj: raise HTTPException(404, "專案錯誤")
    fname = f"{datetime.now().timestamp()}_{file.filename}"
    with open(f"{UPLOAD_DIRECTORY}/{fname}", "wb") as f:
        shutil.copyfileobj(file.file, f)
    proj.status = "submitted"
    proj.submission_file_url = f"/uploads/{fname}"
    db.commit()
    return {"msg": "上傳成功"}

@app.post("/projects/{pid}/complete")
def complete_project(pid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    proj = db.query(Project).filter(Project.id == pid, Project.owner_id == user.id).first()
    if not proj or proj.status != "submitted": raise HTTPException(400, "狀態錯誤")
    proj.status = "completed"
    proj.completed_at = datetime.now()
    db.commit()
    return {"msg": "結案成功"}

@app.post("/projects/{pid}/reject")
def reject_project(pid: int, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    proj = db.query(Project).filter(Project.id == pid, Project.owner_id == user.id).first()
    if not proj or proj.status != "submitted": raise HTTPException(400, "狀態錯誤")
    proj.status = "in_progress"
    db.commit()
    return {"msg": "已退件"}

@app.post("/projects/{pid}/reviews")
def create_review(pid: int, review: ReviewCreate, db: Session = Depends(get_db), user: User = Depends(get_current_user)):
    proj = db.query(Project).filter(Project.id == pid).first()
    if not proj or proj.status != "completed": raise HTTPException(400, "尚未結案")
    
    if user.id == proj.owner_id:
        target_id = proj.selected_freelancer_id
    elif user.id == proj.selected_freelancer_id:
        target_id = proj.owner_id
    else:
        raise HTTPException(403, "非專案參與者")
        
    if db.query(Review).filter(Review.project_id == pid, Review.reviewer_id == user.id).first():
        raise HTTPException(400, "已評價過")

    new_review = Review(
        project_id=pid, reviewer_id=user.id, reviewee_id=target_id,
        rating_1=review.rating_1, rating_2=review.rating_2, rating_3=review.rating_3,
        comment=review.comment
    )
    db.add(new_review)
    db.commit()
    return {"msg": "評價成功"}

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)