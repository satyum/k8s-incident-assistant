FROM python:3.12-slim AS build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
WORKDIR /build
COPY pyproject.toml ./
COPY assistant/ ./assistant/
RUN python -m pip install --prefix=/install .

FROM python:3.12-slim AS runtime
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 RUNBOOK_DIR=/app/runbooks
WORKDIR /app
RUN groupadd --system app && useradd --system --gid app --home-dir /app --no-create-home app
COPY --from=build /install /usr/local
COPY --chown=app:app runbooks/ ./runbooks/
USER app:app
EXPOSE 8000
CMD ["uvicorn", "assistant.main:app", "--host", "0.0.0.0", "--port", "8000"]
