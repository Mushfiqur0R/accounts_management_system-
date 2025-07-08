import os
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# --- এই অংশটি যোগ করা হয়েছে ---
# এটি আপনার app.py থেকে মডেলগুলো ইমপোর্ট করবে যাতে autogenerate কাজ করে
import sys
from dotenv import load_dotenv

# আপনার প্রোজেক্টের রুট ডিরেক্টরিকে পাথে যোগ করুন
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
load_dotenv() # .env ফাইল থেকে ভেরিয়েবল লোড করে

# আপনার app.py থেকে db এবং মডেলগুলো ইমপোর্ট করুন
# নিশ্চিত করুন আপনার app.py ফাইলে db = SQLAlchemy(app) এবং মডেল ক্লাসগুলো সংজ্ঞায়িত আছে
from app import db 
# from app import User, Client, Transaction # উদাহরণ - সব মডেল ইমপোর্ট করার প্রয়োজন নেই, শুধু db.metadata দরকার

# --- পরিবর্তন শেষ ---

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# --- এই অংশটি পরিবর্তন করা হয়েছে ---
# sqlalchemy.url সরাসরি এনভায়রনমেন্ট ভেরিয়েবল থেকে সেট করুন
# এটি Railway-এর DATABASE_URL এবং লোকাল .env ফাইল দুটোকেই সমর্থন করবে
db_url = os.environ.get('DATABASE_URL', 'sqlite:///local_database.db')
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
config.set_main_option('sqlalchemy.url', db_url)
# --- পরিবর্তন শেষ ---

# add your model's MetaData object here
# for 'autogenerate' support
target_metadata = db.metadata # আপনার app.py-এর db অবজেক্টের মেটাডেটা ব্যবহার করুন

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
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
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """
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