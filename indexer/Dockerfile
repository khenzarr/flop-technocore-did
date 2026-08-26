FROM python:3.13-slim
RUN useradd --create-home --uid 10001 indexer
WORKDIR /app
COPY --chown=indexer:indexer worker.py ./worker.py
RUN mkdir -p /data && chown indexer:indexer /data
USER indexer
ENV PYTHONUNBUFFERED=1 TECHNOCORE_INDEX_BIND=0.0.0.0 TECHNOCORE_INDEX_DB=/data/technocore-index.sqlite3
EXPOSE 8788
HEALTHCHECK --interval=30s --timeout=5s --start-period=45s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8788/health', timeout=3).read()"]
CMD ["python", "worker.py"]
