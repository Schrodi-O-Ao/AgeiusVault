#!/bin/sh
set -e

# Automatically run database migrations on container startup
if [ -f "alembic.ini" ]; then
    echo "Running Alembic database migrations..."
    alembic upgrade head || echo "Alembic migration skipped or failed; continuing container startup..."
fi

exec "$@"
