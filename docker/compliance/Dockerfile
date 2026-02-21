FROM python:3.11-slim

LABEL maintainer="stig-ai-lab"
LABEL role="compliance-agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.compliance.txt .
RUN pip install --no-cache-dir -r requirements.compliance.txt

COPY tools/__init__.py              tools/
COPY tools/scanner.py               tools/
COPY agents/__init__.py             agents/
COPY agents/compliance_agent.py     agents/
COPY services/compliance_service.py .

VOLUME ["/reports"]

ENV PYTHONUNBUFFERED=1
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV OLLAMA_MODEL=llama3.1
ENV REPORTS_DIR=/reports

EXPOSE 8004

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
    CMD curl -sf http://localhost:8004/health || exit 1

CMD ["python3", "compliance_service.py"]
