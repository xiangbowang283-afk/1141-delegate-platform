# 【設定】解決套件衝突 (必須在最前面)
import os
os.environ["PASSLIB_BCRYPT_BACKEND"] = "builtin"

import uvicorn
import bcrypt
import shutil
import uuid
from pathlib import Path
from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.staticfiles import StaticFiles

from sqlalchemy import create_engine, Column, Integer, String, Float, ForeignKey, DateTime, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, Session, relationship, joinedload
from pydantic import BaseModel, ConfigDict
import jwt

# --- 1. 資料庫設定 ---
SQLALCHEMY_DATABASE_URL = "sqlite:///./platform.db"
engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# 上傳資料夾
UPLOAD_DIRECTORY = "uploads"
upload_path = Path(UPLOAD_DIRECTORY)
if upload_path.exists():
    if upload_path.is_file():
        try:
            upload_path.unlink()
            upload_path.mkdir(parents=True, exist_ok=True)
        except:
            pass
else:
    upload_path.mkdir(parents=True, exist_ok=True)

# 安全性
SECRET_KEY = "YOUR_SECRET_KEY"  # 上線時請改掉
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- 2. 資料庫模型 ---

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(String, nullable=False)  # "client" or "freelancer"

    projects_owned = relationship("Project", foreign_keys="[Project.owner_id]", back_populates="owner")
    bids = relationship("Bid", back_populates="freelancer")
    projects_assigned = relationship("Project", foreign_keys="[Project.selected_freelancer_id]", back_populates="selected_freelancer")
    ratings_received = relationship("Rating", foreign_keys="[Rating.target_user_id]", back_populates="target_user")

    # Issue 相關
    issues_created = relationship("Issue", back_populates="creator")
    comments_created = relationship("Comment", back_populates="creator")


class Project(Base):
    __tablename__ = "projects"
    id = Column(Integer, primary_key=True, index=True)
    title = Column(String, index=True)
    description = Column(String)
    status = Column(String, default="open")  # open / in_progress / submitted / completed
    owner_id = Column(Integer, ForeignKey("users.id"))
    selected_freelancer_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    submission_file_url = Column(String, nullable=True)
    deadline = Column(DateTime, nullable=True)  # 延伸1：截止時間

    owner = relationship("User", foreign_keys=[owner_id], back_populates="projects_owned")
    selected_freelancer = relationship("User", foreign_keys=[selected_freelancer_id], back_populates="projects_assigned")
    bids = relationship("Bid", back_populates="project", cascade="all, delete-orphan")
    file_history = relationship("FileHistory", back_populates="project", cascade="all, delete-orphan")
    rating = relationship("Rating", back_populates="project", uselist=False)

    # Issue 列表
    issues = relationship("Issue", back_populates="project", cascade="all, delete-orphan")


class FileHistory(Base):
    __tablename__ = "file_history"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    version = Column(Integer)
    file_url = Column(String)
    uploaded_at = Column(DateTime, default=datetime.utcnow)
    project = relationship("Project", back_populates="file_history")


class Bid(Base):
    __tablename__ = "bids"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    freelancer_id = Column(Integer, ForeignKey("users.id"))
    amount = Column(Float)
    proposal_url = Column(String, nullable=True)

    project = relationship("Project", back_populates="bids")
    freelancer = relationship("User", back_populates="bids")


class Rating(Base):
    __tablename__ = "ratings"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    from_user_id = Column(Integer, ForeignKey("users.id"))
    target_user_id = Column(Integer, ForeignKey("users.id"))
    score = Column(Integer)
    comment = Column(String, nullable=True)

    project = relationship("Project", back_populates="rating")
    target_user = relationship("User", foreign_keys="[Rating.target_user_id]", back_populates="ratings_received")


# Issue Tracker 模型
class Issue(Base):
    __tablename__ = "issues"
    id = Column(Integer, primary_key=True, index=True)
    project_id = Column(Integer, ForeignKey("projects.id"))
    creator_id = Column(Integer, ForeignKey("users.id"))
    title = Column(String, nullable=False)
    description = Column(String)
    is_resolved = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    project = relationship("Project", back_populates="issues")
    creator = relationship("User", back_populates="issues_created")
    comments = relationship("Comment", back_populates="issue", cascade="all, delete-orphan")


class Comment(Base):
    __tablename__ = "comments"
    id = Column(Integer, primary_key=True, index=True)
    issue_id = Column(Integer, ForeignKey("issues.id"))
    creator_id = Column(Integer, ForeignKey("users.id"))
    content = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    issue = relationship("Issue", back_populates="comments")
    creator = relationship("User", back_populates="comments_created")


# --- 3. Schemas (Pydantic) ---

class SchemaBase(BaseModel):
    model_config = ConfigDict(from_attributes=True)

# User
class UserBase(SchemaBase):
    username: str


class UserCreate(UserBase):
    password: str
    role: str


class UserInDB(UserBase):
    id: int
    role: str


# Comment
class CommentCreate(SchemaBase):
    content: str


class CommentOut(SchemaBase):
    id: int
    creator: UserInDB
    content: str
    created_at: datetime


# Issue
class IssueCreate(SchemaBase):
    title: str
    description: str


class IssueOut(SchemaBase):
    id: int
    title: str
    description: str
    is_resolved: bool
    created_at: datetime
    creator: UserInDB
    comments: List[CommentOut] = []


# File History
class FileHistoryOut(SchemaBase):
    id: int
    version: int
    file_url: str
    uploaded_at: datetime


# Rating
class RatingCreate(SchemaBase):
    score: int
    comment: Optional[str] = None


class RatingOut(RatingCreate):
    id: int
    from_user_id: int


# Project
class ProjectCreate(SchemaBase):
    title: str
    description: str
    deadline: Optional[datetime] = None


class ProjectUpdate(SchemaBase):
    title: Optional[str] = None
    description: Optional[str] = None
    deadline: Optional[datetime] = None


class ProjectInDB(SchemaBase):
    id: int
    title: str
    description: str
    status: str
    owner_id: int
    selected_freelancer_id: Optional[int] = None
    deadline: Optional[datetime] = None
    submission_file_url: Optional[str] = None

    file_history: List[FileHistoryOut] = []
    rating: Optional[RatingOut] = None
    issues: List[IssueOut] = []


# Bid
class BidCreate(SchemaBase):
    amount: float


class BidInDB(SchemaBase):
    id: int
    amount: float
    freelancer_id: int
    proposal_url: str


class BidInDBWithFreelancer(BidInDB):
    freelancer: UserInDB  # 巢狀 Pydantic 模型


class Token(BaseModel):
    access_token: str
    token_type: str


# --- 4. App 設定與 Helper ---

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/uploads", StaticFiles(directory=UPLOAD_DIRECTORY), name="uploads")
Base.metadata.create_all(bind=engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def get_password_hash(pw: str) -> str:
    b = pw.encode("utf-8")
    if len(b) > 72:
        b = b[:72]
    return bcrypt.hashpw(b, bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        b = plain.encode("utf-8")
        if len(b) > 72:
            b = b[:72]
        return bcrypt.checkpw(b, hashed.encode("utf-8"))
    except:
        return False


def create_access_token(data: dict) -> str:
    to_encode = data.copy()
    to_encode.update({"exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
    except:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="無效的 token")

    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="用戶不存在")
    return user


def get_current_client_user(u: User = Depends(get_current_user)) -> User:
    if u.role != "client":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要 client 身分")
    return u


def get_current_freelancer_user(u: User = Depends(get_current_user)) -> User:
    if u.role != "freelancer":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="需要 freelancer 身分")
    return u


# --- 5. API ---

@app.post("/register", response_model=UserInDB)
def register(user: UserCreate, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == user.username).first():
        raise HTTPException(status_code=400, detail="用戶名已存在")
    db_user = User(
        username=user.username,
        hashed_password=get_password_hash(user.password),
        role=user.role,
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


@app.post("/token", response_model=Token)
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db),
):
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="帳號或密碼錯誤")
    return {
        "access_token": create_access_token({"sub": user.username}),
        "token_type": "bearer",
    }


@app.get("/users/me", response_model=UserInDB)
async def me(u: User = Depends(get_current_user)):
    return u


@app.post("/projects/", response_model=ProjectInDB)
def create_project(
    p: ProjectCreate,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    project_data = p.model_dump()
    if project_data.get("deadline") and project_data["deadline"].tzinfo:
        project_data["deadline"] = project_data["deadline"].replace(tzinfo=None)

    db_p = Project(**project_data, owner_id=u.id, status="open")
    db.add(db_p)
    db.commit()
    db.refresh(db_p)
    return db_p


@app.put("/projects/{pid}", response_model=ProjectInDB)
def update_project(
    pid: int,
    p: ProjectUpdate,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    proj = db.query(Project).filter(Project.id == pid).first()
    if not proj or proj.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if proj.status != "open":
        raise HTTPException(status_code=400, detail="只能修改待委託（open）專案")

    data = p.model_dump(exclude_unset=True)
    if "deadline" in data and data["deadline"] and data["deadline"].tzinfo:
        data["deadline"] = data["deadline"].replace(tzinfo=None)

    for key, val in data.items():
        setattr(proj, key, val)

    db.commit()
    db.refresh(proj)
    return proj


@app.get("/projects/", response_model=List[ProjectInDB])
def read_open_projects(
    keyword: Optional[str] = None,
    db: Session = Depends(get_db),
):
    query = db.query(Project).filter(Project.status == "open")
    if keyword:
        query = query.filter(
            (Project.title.contains(keyword))
            | (Project.description.contains(keyword))
        )
    return query.all()


@app.get("/projects/my", response_model=List[ProjectInDB])
def read_my_projects(
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    return (
        db.query(Project)
        .filter(Project.owner_id == u.id)
        .order_by(Project.id.desc())
        .all()
    )


@app.get("/projects/assigned", response_model=List[ProjectInDB])
def read_assigned_projects(
    db: Session = Depends(get_db),
    u: User = Depends(get_current_freelancer_user),
):
    return (
        db.query(Project)
        .filter(Project.selected_freelancer_id == u.id)
        .order_by(Project.id.desc())
        .all()
    )


@app.post("/projects/{pid}/bid", response_model=BidInDB)
def create_bid(
    pid: int,
    amount: float = Form(...),
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    u: User = Depends(get_current_freelancer_user),
):
    db_project = db.query(Project).filter(Project.id == pid).first()
    if not db_project or db_project.status != "open":
        raise HTTPException(status_code=400, detail="無法投標")
    if db_project.deadline and datetime.utcnow() > db_project.deadline:
        raise HTTPException(status_code=400, detail="已過截止時間")

    safe_filename = f"bid_{pid}_{u.id}_{uuid.uuid4().hex[:8]}.pdf"
    file_path = Path(UPLOAD_DIRECTORY) / safe_filename
    with file_path.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    db_bid = Bid(
        amount=amount,
        project_id=pid,
        freelancer_id=u.id,
        proposal_url=f"/{UPLOAD_DIRECTORY}/{safe_filename}",
    )
    db.add(db_bid)
    db.commit()
    db.refresh(db_bid)
    return db_bid


@app.get("/projects/{pid}/bids", response_model=List[BidInDBWithFreelancer])
def read_project_bids(
    pid: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p or p.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")

    return (
        db.query(Bid)
        .options(joinedload(Bid.freelancer))
        .filter(Bid.project_id == pid)
        .all()
    )


@app.post("/bids/{bid_id}/accept", response_model=ProjectInDB)
def accept_bid(
    bid_id: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    b = (
        db.query(Bid)
        .options(joinedload(Bid.project))
        .filter(Bid.id == bid_id)
        .first()
    )
    if not b:
        raise HTTPException(status_code=404, detail="找不到此投標")
    p = b.project
    if p.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if p.deadline and datetime.utcnow() < p.deadline:
        raise HTTPException(status_code=400, detail="尚未到截止時間")

    p.status = "in_progress"
    p.selected_freelancer_id = b.freelancer_id
    db.commit()
    db.refresh(p)
    return p


@app.post("/projects/{pid}/submit_file", response_model=ProjectInDB)
def submit_file(
    pid: int,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    u: User = Depends(get_current_freelancer_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p or p.selected_freelancer_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if p.status not in ["in_progress", "submitted"]:
        raise HTTPException(status_code=400, detail="目前狀態不可上傳檔案")

    ver = db.query(FileHistory).filter(FileHistory.project_id == pid).count() + 1
    ext = file.filename.split(".")[-1] if "." in file.filename else "bin"
    safe = f"v{ver}_p{pid}_{uuid.uuid4().hex[:8]}.{ext}"
    fpath = Path(UPLOAD_DIRECTORY) / safe
    with fpath.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    h = FileHistory(project_id=pid, version=ver, file_url=f"/{UPLOAD_DIRECTORY}/{safe}")
    db.add(h)
    p.status = "submitted"
    db.commit()
    db.refresh(p)
    return p


@app.post("/projects/{pid}/reject", response_model=ProjectInDB)
def reject_submission(
    pid: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p or p.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if p.status != "submitted":
        raise HTTPException(status_code=400, detail="只有 submitted 狀態可以退件")

    p.status = "in_progress"
    db.commit()
    db.refresh(p)
    return p


@app.post("/projects/{pid}/issues", response_model=IssueOut)
def create_issue(
    pid: int,
    i: IssueCreate,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p or p.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if p.status != "submitted":
        raise HTTPException(status_code=400, detail="尚未提交結案檔案，不能建立 Issue")

    db_issue = Issue(
        project_id=pid,
        creator_id=u.id,
        title=i.title,
        description=i.description,
    )
    db.add(db_issue)
    db.commit()
    db.refresh(db_issue)

    db_issue = (
        db.query(Issue)
        .options(
            joinedload(Issue.creator),
            joinedload(Issue.comments).joinedload(Comment.creator),
        )
        .filter(Issue.id == db_issue.id)
        .first()
    )

    return db_issue


@app.get("/projects/{pid}/issues", response_model=List[IssueOut])
def get_issues(
    pid: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p:
        raise HTTPException(status_code=404, detail="專案不存在")

    if u.id != p.owner_id and u.id != p.selected_freelancer_id:
        raise HTTPException(status_code=403, detail="無權限")

    issues = (
        db.query(Issue)
        .options(
            joinedload(Issue.creator),
            joinedload(Issue.comments).joinedload(Comment.creator),
        )
        .filter(Issue.project_id == pid)
        .all()
    )
    return issues


@app.post("/issues/{iid}/comments")
def create_comment(
    iid: int,
    c: CommentCreate,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_user),
):
    issue = (
        db.query(Issue)
        .options(joinedload(Issue.project))
        .filter(Issue.id == iid)
        .first()
    )
    if not issue:
        raise HTTPException(status_code=404, detail="Issue 不存在")
    p = issue.project

    if u.id != p.owner_id and u.id != p.selected_freelancer_id:
        raise HTTPException(status_code=403, detail="無權限")

    db_c = Comment(issue_id=iid, creator_id=u.id, content=c.content)
    db.add(db_c)
    db.commit()
    db.refresh(db_c)
    return {"message": "回覆成功"}


@app.post("/issues/{iid}/resolve")
def resolve_issue(
    iid: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    issue = (
        db.query(Issue)
        .options(joinedload(Issue.project))
        .filter(Issue.id == iid)
        .first()
    )
    if not issue:
        raise HTTPException(status_code=404, detail="Issue 不存在")
    if issue.project.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")

    issue.is_resolved = True
    db.commit()
    return {"message": "Issue 已解決"}


@app.post("/projects/{pid}/complete", response_model=ProjectInDB)
def complete_project(
    pid: int,
    db: Session = Depends(get_db),
    u: User = Depends(get_current_client_user),
):
    p = db.query(Project).filter(Project.id == pid).first()
    if not p or p.owner_id != u.id:
        raise HTTPException(status_code=403, detail="無權限")
    if p.status != "submitted":
        raise HTTPException(status_code=400, detail="專案尚未提交結案檔案")

    unresolved = (
        db.query(Issue)
        .filter(Issue.project_id == pid, Issue.is_resolved == False)
        .count()
    )
    if unresolved > 0:
        raise HTTPException(status_code=400, detail="仍有未解決的 Issue，無法結案")

    p.status = "completed"
    db.commit()
    db.refresh(p)
    return p


if __name__ == "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
