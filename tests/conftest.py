import os, tempfile, shutil
from pathlib import Path
import pytest
from alembic.config import Config
from alembic import command

TMP=tempfile.mkdtemp(prefix='scamshield-tests-')
os.environ['DATABASE_URL']='sqlite:///'+str(Path(TMP)/'test.db')
os.environ['JWT_SECRET']='test-only-secret-not-for-production-0000000000000000'
from backend import accounts
from backend.db import engine
from backend.main import app
from fastapi.testclient import TestClient

@pytest.fixture(scope='session',autouse=True)
def migrated():
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    command.upgrade(config,'head')
    yield
    engine.dispose();shutil.rmtree(TMP,ignore_errors=True)

@pytest.fixture(autouse=True)
def clear_rate():
    accounts._buckets.clear()
    yield
    accounts._buckets.clear()

@pytest.fixture(autouse=True)
def legacy_auth(request,migrated,clear_rate):
    if request.module.__name__.split('.')[-1] not in ('test_api','test_images','test_integrations'):
        yield
        return
    client=request.module.client
    # unique account for every regression test, exercise real auth layer
    from uuid import uuid4
    r=client.post('/api/auth/register',json={'email':f'{uuid4().hex}@example.com','password':'test-password-long'})
    assert r.status_code==201,r.text
    client.headers['Authorization']='Bearer '+r.json()['access_token']
    yield
    client.headers.pop('Authorization',None)
