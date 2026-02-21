FROM python:3.11-slim

LABEL maintainer="stig-ai-lab"
LABEL role="analyst-agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.analyst.txt .
RUN pip install --no-cache-dir -r requirements.analyst.txt

COPY tools/__init__.py       tools/
COPY tools/scanner.py        tools/
COPY agents/__init__.py      agents/
COPY agents/analyst_agent.py agents/
COPY services/analyst_service.py .

ENV PYTHONUNBUFFERED=1
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV OLLAMA_MODEL=llama3.1

EXPOSE 8002

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
    CMD curl -sf http://localhost:8002/health || exit 1

CMD ["python3", "analyst_service.py"]
