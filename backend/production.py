"""Production configuration validation and request envelope controls."""
import os
import asyncio
import logging
import time
import uuid
from urllib.parse import urlsplit
from fastapi.responses import JSONResponse
from starlette.datastructures import Headers, MutableHeaders
from sqlalchemy import text
from .db import database_url, engine
from . import limits

log = logging.getLogger('uvicorn.error')
CSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' blob:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
HEAD = '0003_rate_counters'

def production(): return os.getenv('APP_ENV') == 'production'

def origins():
    return [x.strip() for x in os.getenv('FRONTEND_ORIGINS','').split(',') if x.strip()]

def hosts():
    return list(dict.fromkeys(['localhost','127.0.0.1'] + [x.strip() for x in os.getenv('ALLOWED_HOSTS','').split(',') if x.strip()] + ([os.environ['RENDER_EXTERNAL_HOSTNAME']] if os.getenv('RENDER_EXTERNAL_HOSTNAME') else [])))

def validate():
    if os.getenv('APP_ENV','development') not in {'development','production','test'}: raise RuntimeError('Invalid APP_ENV')
    if os.getenv('RATE_LIMIT_BACKEND','database' if production() else 'memory') not in {'database','memory'}: raise RuntimeError('Invalid RATE_LIMIT_BACKEND')
    for name, default, cap in [('VIRUSTOTAL_DAILY_LIMIT',500,500),('GEMINI_DAILY_LIMIT',100,100000)]:
        try: value=int(os.getenv(name,str(default)))
        except ValueError: raise RuntimeError('Invalid provider quota') from None
        if not 1 <= value <= cap: raise RuntimeError('Invalid provider quota')
    for origin in origins():
        u=urlsplit(origin)
        if u.scheme not in ({'https'} if production() else {'http','https'}) or not u.hostname or u.username or u.password or '*' in origin or origin != f'{u.scheme}://{u.netloc}': raise RuntimeError('FRONTEND_ORIGINS must contain exact origins, no paths or wildcard')
    if production():
        secret=os.getenv('JWT_SECRET','')
        if len(secret)<43 or len(set(secret))<16 or secret.lower().startswith(('test','change','your_','replace')): raise RuntimeError('Production requires a generated JWT_SECRET')
        if not database_url().startswith('postgresql+psycopg://'): raise RuntimeError('Production requires PostgreSQL')
        if not limits.shared_enabled(): raise RuntimeError('Production requires shared database rate limits')
        if any('*' in h or '/' in h for h in hosts()): raise RuntimeError('Production hosts must be exact hostnames')

def database_ready():
    with engine.connect() as conn:
        if conn.execute(text('SELECT version_num FROM alembic_version')).scalars().all()!=[HEAD]: return False
        for query in ('SELECT is_admin FROM users WHERE 1=0','SELECT 1 FROM login_sessions WHERE 1=0','SELECT 1 FROM scan_records WHERE 1=0','SELECT 1 FROM community_reports WHERE 1=0','SELECT 1 FROM rate_counters WHERE 1=0'):
            conn.execute(text(query))
    return True

class Envelope:
    """Bound JSON body size and time, protect all responses, no payload logging."""
    def __init__(self, app): self.app=app
    async def __call__(self, scope, receive, send):
        if scope['type']!='http': return await self.app(scope,receive,send)
        path=scope['path']; api=path.startswith('/api/'); request_id=uuid.uuid4().hex
        start=time.monotonic(); status=500
        async def safe_send(message):
            nonlocal status
            if message['type']=='http.response.start':
                status=message['status']; h=MutableHeaders(scope=message)
                h['X-Request-ID']=request_id
                h['X-Content-Type-Options']='nosniff'; h['Referrer-Policy']='no-referrer'; h['X-Frame-Options']='DENY'
                h['Permissions-Policy']='camera=(), microphone=(), geolocation=(), payment=()'
                h['Content-Security-Policy']=CSP
                if api: h['Cache-Control']='no-store'
                if production(): h['Strict-Transport-Security']='max-age=31536000'
            await send(message)
        async def error(code, detail):
            await JSONResponse({'detail':detail},status_code=code)(scope,receive,safe_send)
        try:
            if api and scope['method'] in {'POST','PUT','PATCH','DELETE'} and path!='/api/image/extract':
                raw=bytearray(); header=Headers(scope=scope).get('content-length')
                if header is not None:
                    try: length=int(header)
                    except ValueError: return await error(400,'Invalid content length')
                    if length<0: return await error(400,'Invalid content length')
                    if length>65536: return await error(413,'Request body exceeds 64 KiB')
                try:
                    async with asyncio.timeout(10):
                        while True:
                            chunk=await receive()
                            if chunk['type']=='http.disconnect': return
                            data=chunk.get('body',b'')
                            if len(raw)+len(data)>65536: return await error(413,'Request body exceeds 64 KiB')
                            raw.extend(data)
                            if not chunk.get('more_body'): break
                except TimeoutError: return await error(408,'Request body timed out')
                delivered=False
                async def replay():
                    nonlocal delivered
                    if not delivered:
                        delivered=True; return {'type':'http.request','body':bytes(raw),'more_body':False}
                    return await receive()
                await self.app(scope,replay,safe_send)
            else: await self.app(scope,receive,safe_send)
        finally:
            # Avoid path/query strings, user identifiers and exception text in telemetry.
            if production(): log.info('request id=%s method=%s status=%s elapsed_ms=%d',request_id,scope['method'],status,int((time.monotonic()-start)*1000))
