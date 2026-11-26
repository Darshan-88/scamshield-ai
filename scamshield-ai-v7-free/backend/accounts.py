"""Short-lived signed JWTs backed by revocable database sessions."""
import os, re, time, secrets
from datetime import timedelta, timezone
from collections import deque
from threading import Lock, BoundedSemaphore
from contextlib import contextmanager
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import APIRouter, Depends, HTTPException, Request, Response, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
from sqlalchemy import select, delete, func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from . import limits
from .db import User, LoginSession, ScanRecord, get_db, now, uid

router = APIRouter(prefix='/api', tags=['account'])
ISSUER='scamshield-ai'; AUDIENCE='scamshield-web'; TTL=1800
ph=PasswordHasher(time_cost=3,memory_cost=65536,parallelism=2)
dummy_hash=ph.hash(secrets.token_urlsafe(32))
bearer=HTTPBearer(auto_error=False)
_hash_slots=BoundedSemaphore(2)

@contextmanager
def hash_slot():
    if not _hash_slots.acquire(blocking=False):
        raise HTTPException(429,'Authentication service busy. Try again shortly.',headers={'Retry-After':'2'})
    try: yield
    finally: _hash_slots.release()


def secret():
    value=os.getenv('JWT_SECRET','')
    if len(value.encode()) < 32 or value.startswith('YOUR_'):
        raise RuntimeError('Set JWT_SECRET to a random secret of at least 32 bytes in .env.')
    return value

def reject():
    return HTTPException(401,'Invalid or expired session. Sign in again.',headers={'WWW-Authenticate':'Bearer'})

# Single-process sliding windows; fail closed when the bounded bucket map is full.
_lock=Lock(); _buckets={}; WINDOW=60; MAX_BUCKETS=10000

def limit(bucket, identity, maximum):
    if limits.shared_enabled():
        try: allowed, retry = limits.consume(bucket, identity, maximum)
        except limits.LimitUnavailable: raise HTTPException(503, "Rate limiting unavailable. Try again later.") from None
        if not allowed: raise HTTPException(429, "Request limit reached. Try again shortly.", headers={"Retry-After": str(retry)})
        return
    t=time.monotonic(); k=(bucket,identity)
    with _lock:
        if k not in _buckets and len(_buckets)>=MAX_BUCKETS:
            for old,q in list(_buckets.items()):
                if not q or q[-1]<=t-WINDOW: del _buckets[old]
            if len(_buckets)>=MAX_BUCKETS: raise HTTPException(429,'Server busy. Try again later.',headers={'Retry-After':'60'})
        q=_buckets.setdefault(k,deque())
        while q and q[0]<=t-WINDOW: q.popleft()
        if len(q)>=maximum: raise HTTPException(429,'Request limit reached. Try again shortly.',headers={'Retry-After':str(max(1,int(WINDOW-(t-q[0]))+1))})
        q.append(t)

def ip(request): return request.client.host if request.client else 'unknown'

class Credentials(BaseModel):
    email: str=Field(min_length=3,max_length=254)
    password: str=Field(min_length=1,max_length=128)

def email_normalize(raw):
    email=raw.strip().lower()
    if not re.fullmatch(r'[a-z0-9.!#$%&\x27*+/=?^_`{|}~-]+@[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,63}',email) or '..' in email or len(email.split('@')[0])>64:
        raise HTTPException(422,'Enter a valid email address.')
    return email

def issue(db,user):
    stamp=now(); sid=uid(); expiry=stamp+timedelta(seconds=TTL)
    db.execute(delete(LoginSession).where(LoginSession.user_id==user.id,LoginSession.expires_at<=stamp))
    db.add(LoginSession(id=sid,user_id=user.id,expires_at=expiry)); db.commit()
    token=jwt.encode({'sub':user.id,'jti':sid,'iat':stamp,'nbf':stamp,'exp':expiry,'iss':ISSUER,'aud':AUDIENCE},secret(),algorithm='HS256')
    return {'access_token':token,'token_type':'bearer','expires_in':TTL,'user':{'id':user.id,'email':user.email}}

def auth(credentials: HTTPAuthorizationCredentials | None=Depends(bearer),db:Session=Depends(get_db)):
    if not credentials or len(credentials.credentials)>4096: raise reject()
    try:
        claims=jwt.decode(credentials.credentials,secret(),algorithms=['HS256'],issuer=ISSUER,audience=AUDIENCE,options={'require':['sub','jti','iat','nbf','exp','iss','aud']})
        session=db.get(LoginSession,claims['jti'])
        if not session or session.user_id!=claims['sub']: raise reject()
        expiry=session.expires_at
        if expiry.tzinfo is None: expiry=expiry.replace(tzinfo=timezone.utc)
        if expiry<=now(): raise reject()
        user=db.get(User,claims['sub'])
        if not user: raise reject()
        return user,session.id
    except jwt.InvalidTokenError: raise reject() from None

def scan_auth(identity=Depends(auth)):
    limit('scan',identity[0].id,20); return identity[0]

def image_auth(identity=Depends(auth)):
    limit('image',identity[0].id,6); return identity[0]

@router.post('/auth/register',status_code=201)
def register(body:Credentials,request:Request,db:Session=Depends(get_db)):
    limit('register',ip(request),5)
    if os.getenv('APP_ENV')=='production': limit('register_global','all',30)
    email=email_normalize(body.email)
    if len(body.password)<12: raise HTTPException(422,'Use at least 12 characters in your password.')
    with hash_slot(): user=User(email=email,password_hash=ph.hash(body.password))
    db.add(user)
    try: db.flush()
    except IntegrityError:
        db.rollback(); raise HTTPException(409,'Unable to register with this email. Try signing in.') from None
    return issue(db,user)

@router.post('/auth/login')
def login(body:Credentials,request:Request,db:Session=Depends(get_db)):
    limit('login_ip',ip(request),20); email=body.email.strip().lower(); limit('login_email',email,5)
    if os.getenv('APP_ENV')=='production': limit('login_global','all',120)
    user=db.scalar(select(User).where(User.email==email))
    with hash_slot():
        try: valid=ph.verify(user.password_hash if user else dummy_hash,body.password)
        except (VerifyMismatchError,VerificationError,InvalidHashError): valid=False
        if not user or not valid: raise HTTPException(401,'Invalid email or password.')
        if ph.check_needs_rehash(user.password_hash): user.password_hash=ph.hash(body.password)
    return issue(db,user)

@router.get('/auth/me')
def me(identity=Depends(auth)):
    return {'id':identity[0].id,'email':identity[0].email}

@router.post('/auth/logout',status_code=204)
def logout(identity=Depends(auth),db:Session=Depends(get_db)):
    db.execute(delete(LoginSession).where(LoginSession.id==identity[1]));db.commit();return Response(status_code=204)

@router.delete('/auth/account',status_code=204)
def delete_account(body:Credentials,request:Request,identity=Depends(auth),db:Session=Depends(get_db)):
    user=identity[0];limit('delete_account',user.id,5)
    with hash_slot():
        try: valid=ph.verify(user.password_hash,body.password)
        except (VerifyMismatchError,VerificationError,InvalidHashError): valid=False
    if body.email.strip().lower()!=user.email or not valid: raise HTTPException(401,'Account confirmation failed.')
    db.delete(user);db.commit();return Response(status_code=204)

def iso(stamp): return (stamp if stamp.tzinfo else stamp.replace(tzinfo=timezone.utc)).isoformat()

def record_scan(db,user,mode,score,level):
    record=ScanRecord(user_id=user.id,mode=mode,score=score,level=level);db.add(record);db.commit();return record.id

@router.get('/history')
def history(limit:int=Query(30,ge=1,le=100),offset:int=Query(0,ge=0,le=100000),identity=Depends(auth),db:Session=Depends(get_db)):
    user=identity[0]; rows=db.scalars(select(ScanRecord).where(ScanRecord.user_id==user.id).order_by(ScanRecord.created_at.desc(),ScanRecord.id.desc()).offset(offset).limit(limit)).all()
    return {'items':[{'id':r.id,'mode':r.mode,'score':r.score,'level':r.level,'time':iso(r.created_at)} for r in rows]}

@router.delete('/history/{record_id}',status_code=204)
def delete_one(record_id:str,identity=Depends(auth),db:Session=Depends(get_db)):
    result=db.execute(delete(ScanRecord).where(ScanRecord.id==record_id,ScanRecord.user_id==identity[0].id));db.commit()
    if not result.rowcount: raise HTTPException(404,'Scan not found.')
    return Response(status_code=204)

@router.delete('/history',status_code=204)
def clear_history(identity=Depends(auth),db:Session=Depends(get_db)):
    db.execute(delete(ScanRecord).where(ScanRecord.user_id==identity[0].id));db.commit();return Response(status_code=204)

@router.get('/dashboard')
def dashboard(identity=Depends(auth),db:Session=Depends(get_db)):
    owner=ScanRecord.user_id==identity[0].id
    levels=dict(db.execute(select(ScanRecord.level,func.count()).where(owner).group_by(ScanRecord.level)).all())
    modes=dict(db.execute(select(ScanRecord.mode,func.count()).where(owner).group_by(ScanRecord.mode)).all())
    total,avg=db.execute(select(func.count(),func.avg(ScanRecord.score)).where(owner)).one()
    return {'total':total,'average_score':round(float(avg or 0),1),'by_level':{k:levels.get(k,0) for k in ('low','medium','high')},'by_mode':{k:modes.get(k,0) for k in ('message','url','job','banking','screenshot')}}
