from io import StringIO
from pathlib import Path
from alembic import command
from alembic.config import Config

def test_postgres_offline_migration(monkeypatch):
    # Offline DDL only; does not require a real server or driver connection.
    monkeypatch.setenv('DATABASE_URL','postgresql+psycopg://demo:demo@localhost/scamshield')
    buf=StringIO();config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'),output_buffer=buf)
    command.upgrade(config,'head',sql=True)
    ddl=buf.getvalue()
    assert 'CREATE TABLE users' in ddl and 'CREATE TABLE login_sessions' in ddl and 'CREATE TABLE scan_records' in ddl
    assert 'CREATE TABLE community_reports' in ddl and 'ADD COLUMN is_admin' in ddl
    assert 'TIMESTAMP WITH TIME ZONE' in ddl and 'ON DELETE CASCADE' in ddl


def test_v5_upgrade_preserves_accounts_and_history(tmp_path,monkeypatch):
    from sqlalchemy import create_engine,text,inspect
    url='sqlite:///'+str(tmp_path/'upgrade.db');monkeypatch.setenv('DATABASE_URL',url)
    config=Config(str(Path(__file__).resolve().parents[1]/'alembic.ini'))
    command.upgrade(config,'0001_accounts')
    engine=create_engine(url)
    with engine.begin() as c:
        c.execute(text("INSERT INTO users (id,email,password_hash,created_at) VALUES ('u','old@example.com','hash','2026-01-01')"))
        c.execute(text("INSERT INTO scan_records (id,user_id,mode,score,level,created_at) VALUES ('s','u','message',20,'low','2026-01-01')"))
    command.upgrade(config,'head')
    with engine.connect() as c:
        assert c.execute(text("SELECT email,is_admin FROM users WHERE id='u'")).one()==('old@example.com',0)
        assert c.execute(text("SELECT score FROM scan_records WHERE id='s'")).scalar()==20
    assert 'community_reports' in inspect(engine).get_table_names()
    command.downgrade(config,'0001_accounts')
    with engine.connect() as c:
        assert c.execute(text("SELECT email FROM users WHERE id='u'")).scalar()=='old@example.com'
        assert c.execute(text("SELECT score FROM scan_records WHERE id='s'")).scalar()==20
    engine.dispose()
