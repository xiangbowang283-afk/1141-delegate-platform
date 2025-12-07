# 【【【 關鍵修正：解決 passlib 和 bcrypt 的套件衝突 】】】
# 這一行「必須」放在所有 import 的最前面
import os
os.environ["PASSLIB_BCRYPT_BACKEND"] = "builtin"

# ----------------------------------------------------

import uvicorn
import bcrypt # 我們現在直接使用 bcrypt
from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.middleware.cors import CORSMiddleware

from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, Enum
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from pydantic import BaseModel, ConfigDict
from typing import List, Optional, Annotated

import jwt # 我們會使用 PyJWT
from datetime import datetime, timedelta, timezone

import shutil
from pathlib import Path

# --- 1. 資料庫設定 (Database Setup) ---

SQLALCHEMY_DATABASE_URL = "sqlite:///./platform.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 【新】上傳檔案的資料夾
UPLOAD_DIRECTORY = "uploads"

# 【修正 FileExistsError】: 
# 伺服器啟動時，更安全地檢查並建立 uploads 資料夾
upload_path = Path(UPLOAD_DIRECTORY)
if upload_path.exists():
    if upload_path.is_file():
        # 如果 'uploads' 是一個檔案 (不對)，刪除它
        upload_path.unlink()
        upload_path.mkdir(parents=True, exist_ok=True)
else:
    # 如果 'uploads' 不存在，建立它
    upload_path.mkdir(parents=True, exist_ok=True)


# --- 2. 資料庫模型 (Database Models) ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum("client", "freelancer", name="user_roles"), nullable=False)

    # 委託人的關聯
    projects_owned = relationship(
        "Project", 
        foreign_keys="[Project.owner_id]", 
        back_populates="owner"
    )
    
    # 接案人的關聯
    bids = relationship("Bid", back_populates="freelancer")
    
    projects_assigned = relationship(
        "Project", 
        foreign_keys="[Project.selected_freelancer_id]", 
        back_populates="selected_freelancer"
    )

class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True, nullable=False)
    description = Column(String)
    status = Column(String, default="open", nullable=False) # open, in_progress, submitted, completed
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    
    selected_freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    submission_file_url = Column(String, nullable=True)

    # 關聯
    owner = relationship(
        "User", 
        foreign_keys=[owner_id], 
        back_populates="projects_owned"
    )
    selected_freelancer = relationship(
        "User", 
        foreign_keys=[selected_freelancer_id], 
        back_populates="projects_assigned"
    )
    bids = relationship("Bid", back_populates="project", cascade="all, delete-orphan")


class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    message = Column(String, nullable=True) # 【新】儲存承包意願
    
    # 關聯
    project = relationship("Project", back_populates="bids")
    freelancer = relationship("User", back_populates="bids")


# --- 3. Pydantic 資料模型 (Schemas) ---

# User Schemas
class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    role: str # "client" 或 "freelancer"

class UserInDB(UserBase):
    id: int
    role: str
    model_config = ConfigDict(from_attributes=True)

# Project Schemas
class ProjectBase(BaseModel):
    title: str
    description: Optional[str] = None

class ProjectCreate(ProjectBase):
    pass

class ProjectUpdate(ProjectBase):
    pass

class ProjectInDB(ProjectBase):
    id: int
    owner_id: int
    status: str
    selected_freelancer_id: Optional[int] = None
    submission_file_url: Optional[str] = None
    model_config = ConfigDict(from_attributes=True)

# Bid Schemas
class BidBase(BaseModel):
    amount: float
    message: Optional[str] = None

class BidCreate(BidBase):
    pass

# 【【 修正 NameError 】】：我們把 BidInDB 加回來
class BidInDB(BidBase):
    id: int
    project_id: int
    freelancer_id: int
    model_config = ConfigDict(from_attributes=True)

# 【新】用於「查看投標」時，同時回傳接案人資訊
class BidInDBWithFreelancer(BidInDB):
    freelancer: UserInDB # 巢狀 Pydantic 模型

# Token Schemas
class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None


# --- 4. 安全性 & 密碼處理 (Security & Hashing) ---

# 【【 修正：移除 passlib，改用 bcrypt 】】

def get_password_hash(password: str) -> str:
    """使用 bcrypt 加密密碼"""
    password_bytes = password.encode('utf-8')
    # 【修正 72 bytes 錯誤】: bcrypt 只接受 72 bytes
    if len(password_bytes) > 72:
        password_bytes = password_bytes[:72]
        
    pwd_hash = bcrypt.hashpw(password_bytes, bcrypt.gensalt())
    return pwd_hash.decode('utf-8') # 存入資料庫時存為字串

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """驗證密碼"""
    try:
        password_bytes = plain_password.encode('utf-8')
        if len(password_bytes) > 72:
            password_bytes = password_bytes[:72]
            
        hashed_password_bytes = hashed_password.encode('utf-8')
        return bcrypt.checkpw(password_bytes, hashed_password_bytes)
    except Exception:
        return False

# JWT Token 設定
SECRET_KEY = "YOUR_SUPER_SECRET_KEY" # 在生產環境中請務必更換
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """建立 JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now(timezone.utc) + expires_delta
    else:
        expire = datetime.now(timezone.utc) + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# 【【 修正：明確指定 SessionLocal 】】
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: Annotated[str, Depends(oauth2_scheme)], db: Session = Depends(get_db)):
    """解析 token 並獲取目前使用者"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="無法驗證憑證",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except (jwt.PyJWTError, jwt.exceptions.DecodeError): #【修正】捕捉 jwt 錯誤
        raise credentials_exception
    
    user = db.query(User).filter(User.username == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

# 依賴：檢查使用者是否為「委託人」
def get_current_client_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.role != "client":
        raise HTTPException(status_code=403, detail="權限不足：需要委託人身份")
    return current_user

# 依賴：檢查使用者是否為「接案人」
def get_current_freelancer_user(current_user: Annotated[User, Depends(get_current_user)]):
    if current_user.role != "freelancer":
        raise HTTPException(status_code=403, detail="權限不足：需要接案人身份")
    return current_user


# --- 5. FastAPI 應用程式 & 路由 (App & Routes) ---

app = FastAPI()

# 【【【 關鍵修正：將「建立表格」移到這裡 】】】
# 這樣 Uvicorn 啟動時就會執行，而不是等到 __name__ == "__main__"
Base.metadata.create_all(bind=engine)


# CORS 中間件
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # 允許所有來源
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 掛載靜態檔案 (用於提供上傳的檔案)
app.mount("/uploads", StaticFiles(directory=UPLOAD_DIRECTORY), name="uploads")


# --- 使用者認證 (Auth Routes) ---

@app.post("/register", response_model=UserInDB)
def register(user: UserCreate, db: Session = Depends(get_db)):
    """
    註冊新使用者 (委託人或接案人)
    """
    db_user = db.query(User).filter(User.username == user.username).first()
    if db_user:
        raise HTTPException(status_code=400, detail="此用戶名已被註冊")
    
    if user.role not in ["client", "freelancer"]:
        raise HTTPException(status_code=400, detail="無效的角色")
        
    hashed_password = get_password_hash(user.password)
    db_user = User(
        username=user.username, 
        hashed_password=hashed_password, 
        role=user.role
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

@app.post("/token", response_model=Token)
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()], 
    db: Session = Depends(get_db)
):
    """
    使用者登入並獲取 Access Token
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用戶名或密碼不正確",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.get("/users/me", response_model=UserInDB)
async def read_users_me(
    current_user: Annotated[User, Depends(get_current_user)]
):
    """
    獲取目前登入的使用者資訊
    """
    return current_user


# --- 專案 (Project Routes) ---

@app.post("/projects/", response_model=ProjectInDB)
def create_project(
    project: ProjectCreate, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_client_user) # 只有委託人能建立
):
    """
    委託人：建立一個新專案
    """
    db_project = Project(**project.model_dump(), owner_id=current_user.id, status="open")
    db.add(db_project)
    db.commit()
    db.refresh(db_project)
    return db_project

@app.put("/projects/{project_id}", response_model=ProjectInDB)
def update_project(
    project_id: int,
    project_update: ProjectUpdate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    """
    委託人：修改自己的專案 (僅限 open 狀態)
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足，您不是此專案的擁有者")
    if db_project.status != "open":
        raise HTTPException(status_code=400, detail="專案已開始，無法修改")
        
    db_project.title = project_update.title
    db_project.description = project_update.description
    db.commit()
    db.refresh(db_project)
    return db_project

@app.get("/projects/", response_model=List[ProjectInDB])
def read_open_projects(db: Session = Depends(get_db)):
    """
    所有人 (包含接案人)：查看所有「開放中 (open)」的專案
    """
    projects = db.query(Project).filter(Project.status == "open").all()
    return projects

@app.get("/projects/my", response_model=List[ProjectInDB])
def read_my_projects(
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_client_user) # 只有委託人能看
):
    """
    委託人：查看自己建立的「所有」專案 (包含各種狀態)
    """
    projects = db.query(Project).filter(Project.owner_id == current_user.id).order_by(Project.id.desc()).all()
    return projects

@app.get("/projects/assigned", response_model=List[ProjectInDB])
def read_assigned_projects(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_freelancer_user) # 只有接案人能看
):
    """
    接案人：查看「我承接的」專案 (歷史專案列表)
    """
    projects = db.query(Project).filter(Project.selected_freelancer_id == current_user.id).order_by(Project.id.desc()).all()
    return projects


# --- 投標 (Bid Routes) ---

@app.post("/projects/{project_id}/bid", response_model=BidInDB) # 【【 修正：使用 BidInDB 】】
def create_bid(
    project_id: int,
    bid: BidCreate,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_freelancer_user) # 只有接案人能投標
):
    """
    接案人：對一個「開放中」的專案提出投標
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.status != "open":
        raise HTTPException(status_code=400, detail="此專案已關閉投標")

    # 檢查是否已投標
    existing_bid = db.query(Bid).filter(
        Bid.project_id == project_id, 
        Bid.freelancer_id == current_user.id
    ).first()
    if existing_bid:
        raise HTTPException(status_code=400, detail="您已經投標過此專案")

    db_bid = Bid(**bid.model_dump(), project_id=project_id, freelancer_id=current_user.id)
    db.add(db_bid)
    db.commit()
    db.refresh(db_bid)
    return db_bid

@app.get("/projects/{project_id}/bids", response_model=List[BidInDBWithFreelancer])
def read_project_bids(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user) # 只有委託人能看投標
):
    """
    委託人：查看自己專案的「所有」投標
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")

    # 【Bug 修正】: 
    # 使用 joinedload 強制 SQLAlchemy 載入 freelancer 關聯
    bids = db.query(Bid).options(
        joinedload(Bid.freelancer)
    ).filter(Bid.project_id == project_id).all()
    
    return bids

@app.post("/bids/{bid_id}/accept", response_model=ProjectInDB)
def accept_bid(
    bid_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    """
    委託人：接受一個投標，並將專案狀態改為 'in_progress'
    """
    db_bid = db.query(Bid).options(joinedload(Bid.project)).filter(Bid.id == bid_id).first()
    
    if not db_bid:
        raise HTTPException(status_code=404, detail="投標不存在")
    
    db_project = db_bid.project
    if db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    if db_project.status != "open":
        raise HTTPException(status_code=400, detail="專案狀態不是開放中，無法接受投標")

    # 更新專案狀態
    db_project.status = "in_progress"
    db_project.selected_freelancer_id = db_bid.freelancer_id
    
    db.commit()
    db.refresh(db_project)
    return db_project


# --- 結案與檔案上傳 (Submission & File Routes) ---

@app.post("/projects/{project_id}/submit_file", response_model=ProjectInDB)
def submit_file_for_project(
    project_id: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_freelancer_user)
):
    """
    接案人：上傳結案檔案，並將專案狀態改為 'submitted'
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.selected_freelancer_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足，您不是此專案的接案人")
    if db_project.status not in ["in_progress", "submitted"]: # 允許重新提交
        raise HTTPException(status_code=400, detail="專案不是在『進行中』狀態")

    # --- 檔案儲存邏輯 ---
    try:
        # 確保檔案名安全 (可選，但建議)
        safe_filename = f"{datetime.now(timezone.utc).timestamp()}_{file.filename.replace(' ', '_')}"
        file_path = Path(UPLOAD_DIRECTORY) / safe_filename
        
        with file_path.open("wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
            
        file_url = f"/{UPLOAD_DIRECTORY}/{safe_filename}"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"檔案儲存失敗: {e}")
    finally:
        file.file.close()
    
    # 更新專案狀態和檔案 URL
    db_project.status = "submitted"
    db_project.submission_file_url = file_url
    db.commit()
    db.refresh(db_project)
    return db_project

@app.post("/projects/{project_id}/complete", response_model=ProjectInDB)
def complete_project(
    project_id: int,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_client_user)
):
    """
    委託人：接受結案，將專案狀態改為 'completed'
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    if db_project.status != "submitted":
        raise HTTPException(status_code=400, detail="專案不是在『已提交審核』狀態")

    db_project.status = "completed"
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
    委託人：退件，將專案狀態退回 'in_progress'
    """
    db_project = db.query(Project).filter(Project.id == project_id).first()
    
    if not db_project:
        raise HTTPException(status_code=404, detail="專案不存在")
    if db_project.owner_id != current_user.id:
        raise HTTPException(status_code=403, detail="權限不足")
    if db_project.status != "submitted":
        raise HTTPException(status_code=400, detail="專案不是在『已提交審核』狀態")

    db_project.status = "in_progress" # 退回進行中
    db.commit()
    db.refresh(db_project)
    return db_project


# --- 伺服器啟動 (用於本地開發) ---
if __name__ == "__main__":
    # 【【【 關鍵修正：將「建立表格」移到上面 】】】
    # Base.metadata.create_all(bind=engine) # <--- 已移到 app = FastAPI() 之後
    
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)