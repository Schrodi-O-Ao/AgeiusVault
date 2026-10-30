#!/bin/sh
set -e

# Automatically run database migrations on container startup
if [ -f "alembic.ini" ]; then
    echo "Running Alembic database migrations..."
    alembic upgrade head
fi

exec "$@"
