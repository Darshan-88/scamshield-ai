"""Shared fixed-window counters; atomic conditional upsert on PostgreSQL/SQLite."""
import os
import hashlib
import hmac
import time
from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.exc import SQLAlchemyError
from .db import RateCounter, engine

class LimitUnavailable(Exception):
    pass

def shared_enabled():
    return os.getenv('RATE_LIMIT_BACKEND', 'database' if os.getenv('APP_ENV') == 'production' else 'memory') == 'database'

def consume(bucket, identity, maximum, window=60, *, bind=None, timestamp=None):
    """Return (allowed, seconds to reset); no raw user/email/IP stored in counter keys."""
    bind = engine if bind is None else bind
    now = int(time.time() if timestamp is None else timestamp)
    start = now - now % window
    end = start + window
    key = hmac.new(os.environ['JWT_SECRET'].encode(), f'{bucket}\0{identity}\0{window}\0{start}'.encode(), hashlib.sha256).hexdigest()
    table = RateCounter.__table__
    try:
        insert = {'postgresql': pg_insert, 'sqlite': sqlite_insert}[bind.dialect.name]
        stmt = insert(table).values(key=key, count=1, expires_at=end)
        stmt = stmt.on_conflict_do_update(index_elements=[table.c.key], set_={'count':table.c.count+1}, where=table.c.count < maximum).returning(table.c.count)
        with bind.begin() as conn:
            # Expired counters are no longer needed; indexed cleanup on successful DB access.
            conn.execute(delete(table).where(table.c.expires_at <= now))
            allowed = conn.execute(stmt).scalar_one_or_none() is not None
        return allowed, max(1,end-now)
    except (SQLAlchemyError, KeyError) as exc:
        raise LimitUnavailable('Shared rate limiter unavailable') from exc
