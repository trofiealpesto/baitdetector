FROM node:20-bookworm-slim AS frontend-build

WORKDIR /app/frontend

COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    BAITDETECTOR_PROJECT_ROOT=/app \
    PORT=8000

WORKDIR /app

COPY pyproject.toml requirements.txt README.md MODEL_CARD.md ./
COPY src ./src
COPY data/demo ./data/demo
COPY data/models/promoted ./data/models/promoted
COPY --from=frontend-build /app/frontend/dist ./frontend/dist

RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir .

RUN useradd --create-home --shell /bin/bash appuser \
    && chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

CMD ["sh", "-c", "exec uvicorn baitdetector.app:create_app --factory --host 0.0.0.0 --port ${PORT:-8000}"]
