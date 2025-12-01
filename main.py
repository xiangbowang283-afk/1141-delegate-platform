import os
# 解決 passlib 和 bcrypt 的衝突
os.environ["PASSLIB_BCRYPT_BACKEND"] = "builtin"

import uvicorn
import bcrypt
import uuid  # 用於生成唯一檔名
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Enum, DateTime, Text
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Annotated

import jwt
from datetime import datetime, timedelta, timezone
import shutil
from pathlib import Path

# --- 1. 資料庫設定 ---

SQLALCHEMY_DATABASE_URL = "sqlite:///./platform.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

UPLOAD_DIRECTORY = "uploads"
upload_path = Path(UPLOAD_DIRECTORY)
if not upload_path.exists():
    upload_path.mkdir(parents=True, exist_ok=True)

# --- 2. 輔助函數：檔案處理 (防覆蓋) ---

def save_upload_file(upload_file: UploadFile, sub_folder: str = "") -> str:
    """
    儲存上傳的檔案，並確保檔名唯一 (不覆蓋)。
    回傳: 檔案的相對 URL
    """
    try:
        # 產生唯一檔名: Timestamp + UUID + 原始副檔名
        timestamp = int(datetime.now(timezone.utc).timestamp())
        unique_id = str(uuid.uuid4())[:8]
        # 取得原始副檔名 (例如 .pdf)
        orig_filename = upload_file.filename
        ext = os.path.splitext(orig_filename)[1]
        
        # 新檔名
        safe_filename = f"{timestamp}_{unique_id}{ext}"
        
        # 完整路徑
        file_location = upload_path / safe_filename
        
        with file_location.open("wb") as buffer:
            shutil.copyfileobj(upload_file.file, buffer)
            
        return f"/uploads/{safe_filename}"
    finally:
        upload_file.file.close()

# --- 3. 資料庫模型 (Models) ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum("client", "freelancer", name="user_roles"), nullable=False)

    projects_owned = relationship("Project", foreign_keys="[Project.owner_id]", back_populates="owner")
    bids = relationship("Bid", back_populates="freelancer")
    projects_assigned = relationship("Project", foreign_keys="[Project.selected_freelancer_id]", back_populates="selected_freelancer")

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(String)
    status = Column(String, default="open", nullable=False) 
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    # 【新】截止期限
    deadline = Column(DateTime, nullable=True)

    selected_freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    
    # 關聯
    owner = relationship("User", foreign_keys=[owner_id], back_populates="projects_owned")
    selected_freelancer = relationship("User", foreign_keys=[selected_freelancer_id], back_populates="projects_assigned")
    bids = relationship("Bid", back_populates="project", cascade="all, delete-orphan")
    
    # 【新】歷史提交檔案關聯
    submissions = relationship("Submission", back_populates="project", cascade="all, delete-orphan", order_by="desc(Submission.uploaded_at)")

class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    message = Column(String, nullable=True)
    
    # 【新】提案計畫書 (PDF) URL
    proposal_url = Column(String, nullable=True)

    project = relationship("Project", back_populates="bids")
    freelancer = relationship("User", back_populates="bids")

# 【新】歷史版本檔案表格
class Submission(Base):
    __tablename__ = "submissions"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    file_url = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    version_note = Column(String, nullable=True) # 例如: "第1版", "修正版" 等
    
    project = relationship("Project", back_populates="submissions")

# --- 4. Pydantic Schemas ---

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: str

class UserInDB(UserBase):
    id: int
    role: str
    model_config = ConfigDict(from_attributes=True)

# Submission Schema
class SubmissionOut(BaseModel):
    id: int
    file_url: str
    uploaded_at: datetime
    version_note: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

# Project Schemas
class ProjectBase(BaseModel):
    title: str
    description: Optional[str] = None
    deadline: Optional[datetime] = None # 【新】

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(ProjectBase):
    pass

class ProjectInDB(ProjectBase):
    id: int
    owner_id: int
    status: str
    selected_freelancer_id: Optional[int] = None
    submissions: List[SubmissionOut] = [] # 【新】回傳歷史檔案
    model_config = ConfigDict(from_attributes=True)

# Bid Schemas
class BidBase(BaseModel):
    amount: float
    message: Optional[str] = None

# 注意：BidCreate 現在透過 Form Data 傳輸，這裡不需要 Schema，但為了文件化保留 Base

class BidInDB(BidBase):
    id: int
    project_id: int
    freelancer_id: int
    proposal_url: Optional[str] = None # 【新】
    model_config = ConfigDict(from_attributes=True)

class BidInDBWithFreelancer(BidInDB):
    freelancer: UserInDB

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

# --- 5. 安全性 & 依賴 ---

SECRET_KEY = "YOUR_SUPER_SECRET_KEY"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_password_hash(password: str) -> str:
    password_bytes = password.encode('utf-8')
    if len(password_bytes) > 72: password_bytes = password_bytes[:72]
    return bcrypt.hashpw(password_bytes, bcrypt.gensalt()).decode('utf-8')

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72: password_bytes = password_bytes[:72]
        return bcrypt.checkpw(password_bytes, hashed_password.encode('utf-8'))
    except:
        return False

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + (expires_delta if expires_delta else timedelta(minutes=15))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None: raise HTTPException(status_code=401, detail="無效憑證")
    except jwt.PyJWTError:
        raise HTTPException(status_code=401, detail="無效憑證")
    user = db.query(User).filter(User.username == username).first()
    if user is None: raise HTTPException(status_code=401, detail="使用者不存在")
    return user

def get_current_client_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.role != "client": raise HTTPException(status_code=403, detail="需委託人權限")
    return current_user

def get_current_freelancer_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.role != "freelancer": raise HTTPException(status_code=403, detail="需接案人權限")
    return current_user

# --- 6. FastAPI App ---

app = FastAPI()
Base.metadata.create_all(bind=engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIRECTORY), name="uploads")

# --- Auth Routes ---
@app.post("/register", response_model=UserInDB)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="用戶名已存在")
    new_user = User(username=user.username, hashed_password=get_password_hash(user.password), role=user.role)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
async def login(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="登入失敗")
    return {"access_token": create_access_token(data={"sub": user.username}), "token_type": "bearer"}

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(current_user: Annotated[User, Depends(get_current_user)]):
    return current_user

# --- Project Routes ---

@app.post("/projects/", response_model=ProjectInDB)
def create_project(
    project: ProjectCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_client_user)
):
    # 建立專案時接收截止時間
    db_project = Project(
        title=project.title,
        description=project.description,
        deadline=project.deadline,  # 【新】
        owner_id=current_user.id,
        status="open"
    )
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@app.get("/projects/", response_model=List[ProjectInDB])
def read_open_projects(db: Session = Depends(get_db)):
    # 顯示所有專案，前端自己判斷是否過期
    return db.query(Project).filter(Project.status == "open").all()

@app.get("/projects/my", response_model=List[ProjectInDB])
def read_my_projects(db: Session = Depends(get_db), current_user: User = Depends(get_current_client_user)):
    return db.query(Project).filter(Project.owner_id == current_user.id).order_by(Project.id.desc()).all()

@app.get("/projects/assigned", response_model=List[ProjectInDB])
def read_assigned_projects(db: Session = Depends(get_db), current_user: User = Depends(get_current_freelancer_user)):
    return db.query(Project).filter(Project.selected_freelancer_id == current_user.id).order_by(Project.id.desc()).all()

# --- Bid Routes (包含檔案上傳) ---

@app.post("/projects/{project_id}/bid", response_model=BidInDB)
def create_bid(
    project_id: int,
    amount: float = Form(...), # 改用 Form
    message: Optional[str] = Form(None), # 改用 Form
    proposal_file: UploadFile = File(...), # 【新】強制上傳檔案
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_freelancer_user)
):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.status != "open":
        raise HTTPException(status_code=400, detail="專案已關閉")
    
    # 【新】檢查截止日期
    if db_project.deadline and datetime.now(timezone.utc).replace(tzinfo=None) > db_project.deadline:
        raise HTTPException(status_code=400, detail="已超過截止期限，無法提案")

    # 【新】檢查 PDF 格式
    if not proposal_file.filename.lower().endswith('.pdf'):
        raise HTTPException(status_code=400, detail="提案計畫書必須為 PDF 格式")

    # 檢查是否重複投標
    if db.query(Bid).filter(Bid.project_id == project_id, Bid.freelancer_id == current_user.id).first():
        raise HTTPException(status_code=400, detail="您已投標過此專案")

    # 儲存檔案
    proposal_url = save_upload_file(proposal_file)

    db_bid = Bid(
        project_id=project_id,
        freelancer_id=current_user.id,
        amount=amount,
        message=message,
        proposal_url=proposal_url # 【新】
    )
    db.add(db_bid)
    db.commit()
    db.refresh(db_bid)
    return db_bid

@app.get("/projects/{project_id}/bids", response_model=List[BidInDBWithFreelancer])
def read_project_bids(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project or db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    
    return db.query(Bid).options(joinedload(Bid.freelancer)).filter(Bid.project_id == project_id).all()

@app.post("/bids/{bid_id}/accept", response_model=ProjectInDB)
def accept_bid(
    bid_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    db_bid = db.query(Bid).options(joinedload(Bid.project)).filter(Bid.id == bid_id).first()
    if not db_bid: raise HTTPException(status_code=404, detail="投標不存在")
    
    # 這裡不檢查截止日期，因為甲方可以在截止後才進來選擇
    if db_bid.project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")

    db_bid.project.status = "in_progress"
    db_bid.project.selected_freelancer_id = db_bid.freelancer_id
    db.commit()
    db.refresh(db_bid.project)
    return db_bid.project

# --- Submission & Review Routes (歷史版本) ---

@app.post("/projects/{project_id}/submit_file", response_model=ProjectInDB)
def submit_file_for_project(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_freelancer_user)
):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project: raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.selected_freelancer_id != current_user.id:
        raise HTTPException(status_code=403, detail="您不是此專案的接案人")
    # 允許在 submitted 狀態下再次上傳 (即更新版本)
    if db_project.status not in ["in_progress", "submitted"]:
        raise HTTPException(status_code=400, detail="專案狀態不允許提交")

    # 儲存檔案 (檔名自動處理防覆蓋)
    file_url = save_upload_file(file)

    # 【新】新增一筆 Submission 記錄，而不是覆蓋欄位
    new_submission = Submission(
        project_id=project_id,
        file_url=file_url,
        version_note=f"提交於 {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )
    db.add(new_submission)

    # 更新專案狀態
    db_project.status = "submitted"
    
    db.commit()
    db.refresh(db_project)
    return db_project

@app.post("/projects/{project_id}/reject", response_model=ProjectInDB)
def reject_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    """
    【新】甲方退件，讓乙方可以修改後上傳新版本
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project or db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    if db_project.status != "submitted":
        raise HTTPException(status_code=400, detail="只能對已提交的專案進行退件")

    db_project.status = "in_progress" # 退回進行中
    db.commit()
    db.refresh(db_project)
    return db_project

@app.post("/projects/{project_id}/complete", response_model=ProjectInDB)
def complete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project or db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    if db_project.status != "submitted":
        raise HTTPException(status_code=400, detail="專案未處於提交審核狀態")

    db_project.status = "completed"
    db.commit()
    db.refresh(db_project)
    return db_project

if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)