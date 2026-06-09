"""
Configuration Alembic pour les migrations de base de données.
Utilise notre config.py pour la connexion et nos modèles pour l'autogénération.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

from app.core.config import settings
from app.core.database import Base

# Import de tous les modèles pour qu'Alembic les détecte
import app.models  # noqa: F401

# Config Alembic
config = context.config

# On injecte notre DATABASE_URL depuis config.py (au lieu de alembic.ini)
config.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

# Configuration du logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# Metadata de nos modèles — Alembic compare ça avec la base pour générer les migrations
target_metadata = Base.metadata


def run_migrations_offline() -> None:
    """Mode offline : génère le SQL sans se connecter."""
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Mode online : se connecte et exécute les migrations."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection, target_metadata=target_metadata
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
