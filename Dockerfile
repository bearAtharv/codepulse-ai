FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_HOME="/opt/poetry" \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN pip install --no-cache-dir "poetry==${POETRY_VERSION}"

WORKDIR /app

# Copy dependency files first for layer caching
COPY pyproject.toml poetry.lock ./

RUN poetry install --no-ansi --no-root

# Copy source code
COPY . .

# Install the project itself (editable)
RUN poetry install --no-ansi

CMD ["uvicorn", "codepulse.ingestion.app:app", "--host", "0.0.0.0", "--port", "8000"]
