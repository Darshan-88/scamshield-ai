from uuid import uuid4
from fastapi.testclient import TestClient
from sqlalchemy import select, inspect
from backend.main import app
from backend.db import SessionLocal, User, CommunityReport
from backend import accounts
import pytest

client=TestClient(app)
PW='long-test-password-123'
BASE='/api/community'

def account(admin=False):
    email=f'{uuid4().hex}@example.com'
    res=client.post('/api/auth/register',json={'email':email,'password':PW,'is_admin':True})
    assert res.status_code==201,res.text
    data=res.json();user=data['user']
    with SessionLocal() as db:
        u=db.get(User,user['id']);assert u.is_admin is False
        if admin:u.is_admin=True;db.commit()
    return user,{'Authorization':'Bearer '+data['access_token']}

def submit(headers,domain='',**kw):
    return client.post(BASE+'/reports',headers=headers,json={'category':'banking','tactic':'otp_request','domain':domain,'consent':True,**kw})

def moderate(headers,r,status='verified',**kw):
    return client.patch(BASE+'/admin/reports/'+r['id'],headers=headers,json={'status':status,'reason':'independent_review' if status=='verified' else 'insufficient_evidence','revision':r['revision'],'independently_checked':status=='verified',**kw})

def threats(domain):return client.get(BASE+'/threats',params={'domain':domain}).json()['items']

def unique_domain():return uuid4().hex+'.example.com'

@pytest.mark.parametrize('method,path,body',[('post','/reports',{'category':'banking','tactic':'otp_request','consent':True}),('get','/mine',None),('delete','/reports/no-id',None),('get','/admin/reports',None),('patch','/admin/reports/no-id',{'status':'rejected','reason':'insufficient_evidence','revision':0})])
def test_private_routes(method,path,body):
    assert client.request(method,BASE+path,**({'json':body} if body else {})).status_code==401

def test_nonadmin_and_self_moderation():
    u,h=account();r=submit(h).json()
    assert client.get(BASE+'/admin/reports',headers=h).status_code==403
    assert moderate(h,r).status_code==403
    a,ha=account(True);own=submit(ha).json()
    assert moderate(ha,own).status_code==403
    assert client.get(BASE+'/mine',headers=h).json()['is_admin'] is False
    assert client.get(BASE+'/mine',headers=ha).json()['is_admin'] is True
    with SessionLocal() as db:
        db.get(User,a['id']).is_admin=False;db.commit()
    assert client.get(BASE+'/admin/reports',headers=ha).status_code==403

def test_privacy_and_duplicates_and_owner():
    u,h=account();v,hv=account();d=unique_domain()
    a=submit(h,d.upper()+'.');assert a.status_code==201,a.text
    r=a.json();assert r['domain']==d and r['status']=='pending'
    assert 'user_id' not in r and 'reviewer_id' not in r
    assert submit(h,d).status_code==409
    assert submit(hv,d).status_code==201
    assert client.get(BASE+'/mine',headers=h).json()['items']==[r]
    assert client.delete(BASE+'/reports/'+r['id'],headers=hv).status_code==404
    assert threats(d)==[]
    with SessionLocal() as db:
        assert set(inspect(db.get(CommunityReport,r['id'])).mapper.columns.keys())=={'id','user_id','category','tactic','domain','status','created_at','reviewed_at','reviewer_id','review_reason','revision'}

@pytest.mark.parametrize('bad',['https://example.com/private?token=abc','user@example.com','127.0.0.1','localhost','server.internal','a..com','<script>.com','a.com:443','user.private.com','a.onion','foo.com/path'])
def test_invalid_domain(bad):
    _,h=account();r=submit(h,bad);assert r.status_code==422 and bad not in r.text

@pytest.mark.parametrize('extra',[{'consent':False},{'raw_message':'secret OTP 1234'},{'status':'verified'},{'category':'<script>'},{'tactic':'phone number 1234'}])
def test_structured_only(extra):
    _,h=account();r=submit(h,**extra);assert r.status_code==422 and 'secret OTP' not in r.text

def test_moderation_lifecycle_search_and_analytics():
    _,h=account();_,hv=account();_,ha=account(True);d=unique_domain()
    r=submit(h,d).json();s=submit(hv,d).json()
    before=client.get(BASE+'/analytics').json()['verified_reports'];assert threats(d)==[]
    assert moderate(ha,r,independently_checked=False).status_code==422
    assert moderate(ha,r,reason='other').status_code==422
    rev=moderate(ha,r);assert rev.status_code==200,rev.text;r1=rev.json();assert r1['revision']==1
    assert moderate(ha,r).status_code==409
    rows=threats(d);assert len(rows)==1 and rows[0]['report_count']==1 and rows[0]['domain']==d.replace('.','[.]')
    assert set(rows[0])=={'category','tactic','domain','status','report_count'}
    assert client.get(BASE+'/threats',params={'domain':d,'category':'job'}).json()['items']==[]
    assert client.get(BASE+'/threats',params={'domain':d,'tactic':'otp_request'}).json()['items']==rows
    assert client.get(BASE+'/analytics').json()['verified_reports']==before+1
    assert moderate(ha,s).status_code==200;assert threats(d)[0]['report_count']==2
    rejected=moderate(ha,r1,'rejected');assert rejected.status_code==200
    assert threats(d)[0]['report_count']==1
    assert client.delete(BASE+'/reports/'+s['id'],headers=hv).status_code==204
    assert threats(d)==[] and client.get(BASE+'/analytics').json()['verified_reports']==before
    assert client.get(BASE+'/mine',headers=h).json()['items'][0]['status']=='rejected'
    assert moderate(ha,rejected.json(),'pending').status_code==200
    assert threats(d)==[]

def test_account_deletion_removes_report_and_contribution():
    u,h=account();a,ha=account(True);d=unique_domain();r=submit(h,d).json()
    assert moderate(ha,r).status_code==200
    assert threats(d)
    assert client.request('DELETE','/api/auth/account',headers=h,json={'email':u['email'],'password':PW}).status_code==204
    assert threats(d)==[]
    with SessionLocal() as db: assert db.get(CommunityReport,r['id']) is None

def test_report_rate_limit():
    _,h=account()
    for _ in range(5):assert submit(h,unique_domain()).status_code==201
    r=submit(h,unique_domain());assert r.status_code==429 and int(r.headers['retry-after'])>0

def test_paging_and_queue():
    _,ha=account(True);_,h=account();d=unique_domain();r=submit(h,d).json()
    q=client.get(BASE+'/admin/reports',params={'status':'pending','offset':0},headers=ha);assert q.status_code==200 and len(q.json()['items'])<=20
    assert client.get(BASE+'/admin/reports',params={'status':'pending','offset':100000},headers=ha).json()=={'items':[],'has_more':False}
    assert client.get(BASE+'/mine',headers=h,params={'offset':20}).json()['items']==[]
    assert client.get(BASE+'/threats',params={'offset':-1}).status_code==422
    assert client.get(BASE+'/threats',params={'domain':'%'}).status_code==422


def test_operator_cli_grant_and_revoke(monkeypatch):
    import sys
    from backend.manage_admin import main
    user,h=account()
    monkeypatch.setattr(sys,'argv',['manage_admin','grant',user['id']]);main()
    assert client.get(BASE+'/admin/reports',headers=h).status_code==200
    monkeypatch.setattr(sys,'argv',['manage_admin','revoke',user['id']]);main()
    assert client.get(BASE+'/admin/reports',headers=h).status_code==403


def test_deleted_moderator_preserves_other_report_without_reviewer():
    _,h=account();a,ha=account(True);d=unique_domain();r=submit(h,d).json()
    assert moderate(ha,r).status_code==200
    assert client.request('DELETE','/api/auth/account',headers=ha,json={'email':a['email'],'password':PW}).status_code==204
    assert threats(d)[0]['report_count']==1
    with SessionLocal() as db:
        assert db.get(CommunityReport,r['id']).reviewer_id is None
    assert client.delete(BASE+'/reports/'+r['id'],headers=h).status_code==204
