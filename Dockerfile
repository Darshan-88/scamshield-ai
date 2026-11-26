FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1 OMP_NUM_THREADS=1 OPENBLAS_NUM_THREADS=1 MKL_NUM_THREADS=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends tesseract-ocr tesseract-ocr-eng libglib2.0-0 libgomp1 && rm -rf /var/lib/apt/lists/*
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY backend backend
COPY frontend frontend
COPY migrations migrations
COPY data data
COPY scripts scripts
COPY alembic.ini ./
ARG FETCH_UCI_DATASET=0
RUN if [ "$FETCH_UCI_DATASET" = 1 ]; then python scripts/import_dataset.py; fi
RUN groupadd --system app && useradd --system --gid app --home-dir /app app && chown -R app:app /app
USER app
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=8s --start-period=60s --retries=3 CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:'+os.getenv('PORT','8000')+'/api/health/ready',timeout=6).close()"
# Migrations run separately by Compose or Render pre-deploy hook.
CMD ["sh","scripts/start.sh"]
