from pathlib import Path
from contextlib import asynccontextmanager
from .ml import get_model, predict
from .integrations import configuration, reputation, explain
import re, ipaddress, asyncio
from urllib.parse import urlsplit
from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.concurrency import run_in_threadpool
from . import images
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session
from sqlalchemy import text as sql_text
from .db import get_db, engine, User
from . import accounts, community, production as prod
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware
from sqlalchemy.exc import SQLAlchemyError

@asynccontextmanager
async def lifespan(app):
    accounts.secret()
    prod.validate()
    if not prod.database_ready(): raise RuntimeError('Database migration required: alembic upgrade head')
    model, info = get_model()
    if __import__('os').getenv('REQUIRE_REAL_DATASET') == '1' and not info.get('real_dataset',False): raise RuntimeError('Real dataset required: see training instructions')
    yield

app = FastAPI(title='ScamShield AI', version='0.7.0', lifespan=lifespan, docs_url=None if prod.production() else '/docs', redoc_url=None if prod.production() else '/redoc', openapi_url=None if prod.production() else '/openapi.json')
app.include_router(accounts.router)
app.include_router(community.router)

@app.exception_handler(RequestValidationError)
async def safe_validation_error(request, exc):
    # Do not reflect passwords, submitted scam text or other sensitive inputs.
    return JSONResponse(status_code=422,content={'detail':'Invalid request. Check input format and length.'})

if prod.production():
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=prod.hosts())
app.add_middleware(prod.Envelope)
app.add_middleware(CORSMiddleware, allow_origins=prod.origins(), allow_methods=['GET','POST','PATCH','DELETE'], allow_headers=['Authorization','Content-Type'], expose_headers=['Retry-After','X-Request-ID'], allow_credentials=False)

@app.exception_handler(SQLAlchemyError)
async def database_error(request, exc):
    return JSONResponse(status_code=503, content={'detail':'Database unavailable. Try again later.'}, headers={'Cache-Control':'no-store'})

RULES = [
 ('Urgency or intimidation', r'\b(urgent|immediately|blocked|suspended|arrest|last chance|within \d+ hours?)\b', 20),
 ('Unexpected reward', r'\b(lottery|won|prize|guaranteed returns?|free gift)\b', 25),
 ('Advance payment request', r'\b(registration fee|processing fee|advance payment|security deposit|pay.*fee)\b', 30),
 ('Credential or OTP request', r'\b(share|send|enter|provide|verify|tell|submit)\b.{0,45}\b(otp|password|pin|cvv|seed phrase)\b', 40),
 ('Financial impersonation indicator', r'\b(kyc|digital arrest|customs officer|bank officer|income tax officer)\b', 20),
 ('Unrealistic job offer', r'\b(no interview|earn daily|easy money|work from home.*guaranteed)\b', 25),
 ('Link-based call to action', r'\b(click|open|visit|tap)\b.{0,30}\b(link|https?)\b', 15),
 ('Remote access request', r'\b(anydesk|teamviewer|screen sharing|remote access)\b', 25),
]
class ScanRequest(BaseModel):
    text: str = Field(min_length=1,max_length=12000)
    mode: str = Field(default='message',pattern='^(message|url|job|banking|screenshot)$')
    use_gemini: bool = False
    use_reputation: bool = False
    save_history: bool = True

def url_signals(raw):
    findings=[]
    try:
        u=urlsplit(raw if '://' in raw else 'https://'+raw)
        host=u.hostname
        if not host or not re.fullmatch(r'[\w.:-]+',host): return [('Malformed or unusual URL',20)]
        if u.scheme not in ('http','https'): findings.append(('Unusual URL scheme',25))
        if u.scheme=='http': findings.append(('Unencrypted HTTP connection',10))
        if u.username or u.password: findings.append(('Credentials embedded in URL',35))
        if 'xn--' in host: findings.append(('Internationalized domain: verify spelling',15))
        try:
            ipaddress.ip_address(host); findings.append(('IP address used instead of domain',25))
        except ValueError: pass
        if host in {'bit.ly','tinyurl.com','t.co','cutt.ly','is.gd'}: findings.append(('Shortened link hides destination',20))
        if host.count('.')>=4: findings.append(('Unusually deep subdomain',15))
        if re.search(r'(verify|secure|login|kyc|update|wallet|claim)',host,re.I): findings.append(('Sensitive-action keyword in domain',15))
    except ValueError: findings.append(('Malformed URL',20))
    return findings

@app.get('/api/health')
def health(): return {'status':'ok','engine':'hybrid-v7'}

@app.get('/api/health/live')
def live(): return {'status':'ok'}

@app.get('/api/health/ready')
def ready():
    try:
        if not prod.database_ready(): raise RuntimeError('migration')
        _, info = get_model()
        if __import__('os').getenv('REQUIRE_REAL_DATASET') == '1' and not info.get('real_dataset',False): raise RuntimeError('dataset')
    except Exception:
        return JSONResponse(status_code=503,content={'status':'not_ready'})
    return {'status':'ready'}

@app.get('/api/integrations')
def integrations_info():
    return configuration()

@app.get('/api/model')
def model_info():
    return get_model()[1]

@app.get('/api/image/capabilities')
def image_capabilities():
    return capabilities_response(images.capabilities())

def capabilities_response(data):
    from fastapi.responses import JSONResponse
    return JSONResponse(data, headers={'Cache-Control':'no-store'})

@app.post('/api/image/extract')
async def image_extract(request: Request, user: User=Depends(accounts.image_auth)):
    # Raw bytes, not multipart: avoid framework upload spooling to disk.
    mime = request.headers.get('content-type', '').split(';', 1)[0].strip().lower()
    if mime not in images.MIME_FORMAT:
        raise HTTPException(415, 'Use a PNG, JPEG or WebP image.')
    length = request.headers.get('content-length')
    if length is not None:
        try:
            n = int(length)
        except ValueError:
            raise HTTPException(400, 'Invalid content length') from None
        if n > images.MAX_BYTES:
            raise HTTPException(413, 'Image exceeds 8 MiB.')
    if not images.SLOTS.acquire(blocking=False):
        raise HTTPException(429, 'Image scanner is busy. Try again shortly.')
    try:
        raw = bytearray()
        try:
            async with asyncio.timeout(20):
                async for chunk in request.stream():
                    if len(raw) + len(chunk) > images.MAX_BYTES:
                        raise HTTPException(413, 'Image exceeds 8 MiB.')
                    raw.extend(chunk)
        except TimeoutError:
            raise HTTPException(408, 'Image upload timed out.') from None
        if not raw:
            raise HTTPException(422, 'Choose a non-empty image.')
        try:
            data = await run_in_threadpool(images.extract_image, bytes(raw), mime)
        except images.ImageInputError as exc:
            raise HTTPException(422, str(exc)) from None
        return capabilities_response(data)
    finally:
        images.SLOTS.release()

@app.post('/api/scan')
def scan(req:ScanRequest, user: User=Depends(accounts.scan_auth), db: Session=Depends(get_db)):
    text=req.text.strip()
    if not text: raise HTTPException(422,'Enter non-empty content')
    findings=[(name,weight) for name,pattern,weight in RULES if re.search(pattern,text,re.I|re.S)]
    urls=[text] if req.mode=='url' else re.findall(r'https?://[^\s<>"\']+',text,re.I)[:20]
    if req.mode=='url' and (any(c.isspace() for c in text) or '.' not in text): raise HTTPException(422,'Enter a valid URL or domain')
    urls=list(dict.fromkeys(url.rstrip('.,)') for url in urls))
    for url in urls: findings.extend(url_signals(url))
    if req.mode=='screenshot' and re.search(r'\bupi://(?:pay|mandate)\b', text, re.I):
        findings.append(('UPI payment or mandate request: verify recipient before approving',20))
    unique=dict(findings)
    rule_score=min(100,sum(unique.values()))
    ml=None if req.mode=='url' else predict(text)
    # ML may raise risk, never override explicit warning signs. Low scores are not proof of safety.
    ml_contribution=0 if ml is None else max(0,round((ml['spam_score']-50)*1.6))
    rep=reputation(urls,req.use_reputation)
    score=max(rule_score,ml_contribution,rep['risk_floor'])
    level='high' if score>=60 else 'medium' if score>=30 else 'low'
    advice=['Verify the sender through an independently obtained official contact.','Never share OTPs, PINs or passwords, or pay unexpected fees.']
    if req.mode=='screenshot': advice.append('Review extracted text and QR payloads against the original image. A QR code alone does not prove fraud. Do not scan unknown payment codes to receive money.')
    if urls: advice.append('Do not open suspicious links; navigate to the official website yourself.')
    if level=='high': advice.append('Stop interacting with the sender. If money was lost in India, contact your bank and call 1930 promptly.')
    details=[{'label':k,'weight':v} for k,v in unique.items()]
    explanation=explain(text,req.mode,details,score,rep,req.use_gemini)
    record_id=accounts.record_scan(db,user,req.mode,score,level) if req.save_history else None
    return {'history_id':record_id,'reputation':rep,'explanation':explanation,'score':score,'rule_score':rule_score,'ml':ml,'ml_contribution':ml_contribution,'level':level,'findings':details, 'advice':advice,'engine':'hybrid-v7','disclaimer':'Hybrid risk indicator, not a fraud probability or proof of safety. Text model is experimental; a missing or unflagged reputation report does not establish safety. AI explanations may be incorrect.'}

app.mount('/',StaticFiles(directory=Path(__file__).resolve().parents[1]/'frontend',html=True),name='frontend')
