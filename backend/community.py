"""Structured, moderated community indicators. No messages, phone numbers, or links."""
import re
from typing import Literal
from fastapi import APIRouter, Depends, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field, ConfigDict
from sqlalchemy import select, func, delete, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from . import accounts
from .db import CommunityReport as Report, get_db, now

router=APIRouter(prefix='/api/community',tags=['community'])
Category=Literal['banking','job','shopping','investment','lottery','impersonation','phishing','other']
Tactic=Literal['otp_request','advance_fee','urgent_pressure','fake_reward','credential_request','payment_request','remote_access','fake_identity','suspicious_link','other']
Status=Literal['pending','verified','rejected']
Reason=Literal['independent_review','insufficient_evidence','privacy_risk','incorrect_category','misleading','other']
CATEGORIES=Category.__args__; TACTICS=Tactic.__args__

class Submission(BaseModel):
    model_config=ConfigDict(extra='forbid')
    category:Category
    tactic:Tactic
    domain:str=Field(default='',max_length=253)
    consent:Literal[True]

class Review(BaseModel):
    model_config=ConfigDict(extra='forbid')
    status:Status
    reason:Reason
    revision:int=Field(ge=0)
    independently_checked:bool=False

# Syntax filter only: never resolves DNS, fetches websites, or asserts a host is public.
def normalize_domain(raw):
    value=raw.strip().lower().rstrip('.')
    if not value: return ''
    labels=value.split('.')
    if (len(labels)<2 or len(value)>253 or not re.fullmatch(r'[a-z]{2,63}',labels[-1])
        or labels[-1] in {'local','localhost','internal','invalid','test','example','onion','lan','home','corp','arpa'}
        or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',x) or x.startswith('xn--') for x in labels)
        or any(x in {'localhost','internal','intranet','private'} for x in labels)):
        raise HTTPException(422,'Enter only a public-facing ASCII domain, without URL paths, IPs, email addresses or private hosts. Leave blank if unsure.')
    return value

def admin(identity=Depends(accounts.auth)):
    if not identity[0].is_admin: raise HTTPException(403,'Moderator permission required.')
    return identity[0]

def own_row(r):
    return {'id':r.id,'category':r.category,'tactic':r.tactic,'domain':r.domain,'status':r.status,
            'created_at':accounts.iso(r.created_at),'reviewed_at':accounts.iso(r.reviewed_at) if r.reviewed_at else None,
            'review_reason':r.review_reason,'revision':r.revision}

@router.post('/reports',status_code=201)
def submit(body:Submission,request:Request,identity=Depends(accounts.auth),db:Session=Depends(get_db)):
    user=identity[0];accounts.limit('report_create',user.id,5);accounts.limit('report_ip',accounts.ip(request),15)
    domain=normalize_domain(body.domain)
    r=Report(user_id=user.id,category=body.category,tactic=body.tactic,domain=domain)
    db.add(r)
    try: db.commit()
    except IntegrityError:
        db.rollback();raise HTTPException(409,'You already reported this category, tactic and domain.') from None
    return own_row(r)

@router.get('/mine')
def mine(offset:int=Query(0,ge=0,le=100000),identity=Depends(accounts.auth),db:Session=Depends(get_db)):
    user=identity[0];accounts.limit('report_mine',user.id,60)
    rows=db.scalars(select(Report).where(Report.user_id==user.id).order_by(Report.created_at.desc(),Report.id.desc()).offset(offset).limit(21)).all()
    return {'items':[own_row(r) for r in rows[:20]],'has_more':len(rows)>20,'is_admin':user.is_admin}

@router.delete('/reports/{report_id}',status_code=204)
def withdraw(report_id:str,identity=Depends(accounts.auth),db:Session=Depends(get_db)):
    user=identity[0];accounts.limit('report_withdraw',user.id,20)
    result=db.execute(delete(Report).where(Report.id==report_id,Report.user_id==user.id))
    if not result.rowcount: raise HTTPException(404,'Report not found.')
    db.commit();return Response(status_code=204)

@router.get('/threats')
def threats(request:Request,category:Category|None=None,tactic:Tactic|None=None,domain:str=Query('',max_length=253),offset:int=Query(0,ge=0,le=100000),db:Session=Depends(get_db)):
    accounts.limit('public_threats',accounts.ip(request),60)
    conditions=[Report.status=='verified']
    if category: conditions.append(Report.category==category)
    if tactic: conditions.append(Report.tactic==tactic)
    if domain.strip(): conditions.append(Report.domain==normalize_domain(domain))
    count=func.count(Report.id)
    rows=db.execute(select(Report.category,Report.tactic,Report.domain,count.label('count')).where(*conditions)
        .group_by(Report.category,Report.tactic,Report.domain).order_by(count.desc(),Report.category,Report.tactic,Report.domain).offset(offset).limit(21)).all()
    return {'items':[{'category':r.category,'tactic':r.tactic,'domain':r.domain.replace('.','[.]'),'status':'verified','report_count':r.count} for r in rows[:20]],'has_more':len(rows)>20,'note':'Moderator-reviewed reports are community claims, not proof of fraud. No match does not establish safety.'}

@router.get('/analytics')
def analytics(request:Request,db:Session=Depends(get_db)):
    accounts.limit('public_analytics',accounts.ip(request),60)
    only=Report.status=='verified'
    categories=dict(db.execute(select(Report.category,func.count()).where(only).group_by(Report.category)).all())
    tactics=dict(db.execute(select(Report.tactic,func.count()).where(only).group_by(Report.tactic)).all())
    groups=select(Report.category,Report.tactic,Report.domain).where(only).group_by(Report.category,Report.tactic,Report.domain).subquery()
    return {'verified_reports':sum(categories.values()),'distinct_indicators':db.scalar(select(func.count()).select_from(groups)),
            'by_category':{k:categories.get(k,0) for k in CATEGORIES},'by_tactic':{k:tactics.get(k,0) for k in TACTICS},
            'note':'Counts reflect currently published reports, not verified victims or population-level scam prevalence.'}

@router.get('/admin/reports')
def queue(status:Status='pending',offset:int=Query(0,ge=0,le=100000),user=Depends(admin),db:Session=Depends(get_db)):
    accounts.limit('moderation_read',user.id,60)
    rows=db.scalars(select(Report).where(Report.status==status).order_by(Report.created_at,Report.id).offset(offset).limit(21)).all()
    return {'items':[dict(own_row(r), own_report=r.user_id==user.id) for r in rows[:20]],'has_more':len(rows)>20}

@router.patch('/admin/reports/{report_id}')
def moderate(report_id:str,body:Review,user=Depends(admin),db:Session=Depends(get_db)):
    accounts.limit('moderation_write',user.id,30)
    r=db.get(Report,report_id)
    if not r: raise HTTPException(404,'Report not found.')
    if r.user_id==user.id: raise HTTPException(403,'Moderators cannot review their own reports.')
    if body.status=='verified' and (not body.independently_checked or body.reason!='independent_review'):
        raise HTTPException(422,'Confirm independent evidence review before publishing.')
    if body.status!='verified' and body.reason=='independent_review':
        raise HTTPException(422,'Choose a non-verification reason.')
    result=db.execute(update(Report).where(Report.id==report_id,Report.revision==body.revision).values(
        status=body.status,review_reason=body.reason,reviewed_at=now(),reviewer_id=user.id,revision=Report.revision+1))
    if not result.rowcount: db.rollback();raise HTTPException(409,'Report changed. Reload the moderation queue.')
    db.commit();db.refresh(r);return own_row(r)
