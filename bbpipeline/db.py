from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from functools import lru_cache

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.orm import Session, sessionmaker

from bbpipeline.models import Base
from bbpipeline.settings import Settings, get_settings


@lru_cache(maxsize=8)
def engine_for(url: str) -> Engine:
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, pool_pre_ping=True, future=True, connect_args=connect_args)


def get_engine(settings: Settings | None = None) -> Engine:
    active = settings or get_settings()
    return engine_for(active.resolved_database_url)


def session_factory(settings: Settings | None = None) -> sessionmaker[Session]:
    return sessionmaker(bind=get_engine(settings), expire_on_commit=False, future=True)


@contextmanager
def session_scope(settings: Settings | None = None) -> Generator[Session, None, None]:
    session = session_factory(settings)()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def init_db(settings: Settings | None = None) -> None:
    Base.metadata.create_all(get_engine(settings))


def db_ready(settings: Settings | None = None) -> bool:
    try:
        with get_engine(settings).connect() as connection:
            connection.execute(text("SELECT 1"))
        return True
    except Exception:
        return False
