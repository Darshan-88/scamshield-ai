"""SQLAlchemy database configuration and metadata-only persistence."""
import os
from pathlib import Path
from datetime import datetime, timezone
from uuid import uuid4
from dotenv import load_dotenv
from sqlalchemy import BigInteger, String, Integer, Boolean, UniqueConstraint, ForeignKey, DateTime, CheckConstraint, Index, create_engine, event, false
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

ROOT = Path(__file__).resolve().parents[1]
load_dotenv(ROOT / '.env', override=False)

def database_url():
    url = os.getenv('DATABASE_URL') or f'sqlite:///{(ROOT / "scamshield.db").as_posix()}'
    if url.startswith('postgres://'): url = 'postgresql+psycopg://' + url[len('postgres://'):]
    if url.startswith('postgresql://'): url = 'postgresql+psycopg://' + url[len('postgresql://'):]
    return url

def now(): return datetime.now(timezone.utc)
def uid(): return str(uuid4())

class Base(DeclarativeBase): pass

class User(Base):
    __tablename__ = 'users'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    email: Mapped[str] = mapped_column(String(254), unique=True, nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False, server_default=false())
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)

class LoginSession(Base):
    __tablename__ = 'login_sessions'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)

class ScanRecord(Base):
    __tablename__ = 'scan_records'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    mode: Mapped[str] = mapped_column(String(16), nullable=False)
    score: Mapped[int] = mapped_column(Integer, nullable=False)
    level: Mapped[str] = mapped_column(String(8), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    __table_args__ = (CheckConstraint('score >= 0 AND score <= 100',name='ck_scan_score'), CheckConstraint("level IN ('low','medium','high')",name='ck_scan_level'), CheckConstraint("mode IN ('message','url','job','banking','screenshot')",name='ck_scan_mode'), Index('ix_scan_user_time','user_id','created_at','id'))

def make_engine(url=None):
    url = url or database_url()
    engine = create_engine(url, pool_pre_ping=True, **({'connect_args':{'check_same_thread':False}} if url.startswith('sqlite') else {'connect_args':{'connect_timeout':5, 'options':'-c statement_timeout=10000'},'pool_timeout':5,'pool_size':5,'max_overflow':5}))
    if engine.dialect.name == 'sqlite':
        @event.listens_for(engine,'connect')
        def foreign_keys(connection, _):
            connection.execute('PRAGMA foreign_keys=ON')
    return engine

engine = make_engine()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

def get_db():
    with SessionLocal() as db:
        yield db

class CommunityReport(Base):
    __tablename__ = 'community_reports'
    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=uid)
    user_id: Mapped[str] = mapped_column(ForeignKey('users.id', ondelete='CASCADE'), nullable=False)
    category: Mapped[str] = mapped_column(String(24), nullable=False)
    tactic: Mapped[str] = mapped_column(String(32), nullable=False)
    domain: Mapped[str] = mapped_column(String(253), nullable=False, default='')
    status: Mapped[str] = mapped_column(String(12), nullable=False, default='pending')
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=now)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    reviewer_id: Mapped[str | None] = mapped_column(ForeignKey('users.id', ondelete='SET NULL'), nullable=True)
    review_reason: Mapped[str | None] = mapped_column(String(32), nullable=True)
    revision: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    __table_args__ = (
        UniqueConstraint('user_id','category','tactic','domain',name='uq_report_indicator_owner'),
        CheckConstraint("status IN ('pending','verified','rejected')",name='ck_report_status'),
        Index('ix_report_public','status','category','tactic','domain'),
        Index('ix_report_owner_time','user_id','created_at','id'),
        Index('ix_report_review_queue','status','created_at','id'),
    )

class RateCounter(Base):
    __tablename__ = 'rate_counters'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer, nullable=False)
    expires_at: Mapped[int] = mapped_column(BigInteger, nullable=False, index=True)
    __table_args__ = (CheckConstraint('count > 0', name='ck_rate_positive'),)
