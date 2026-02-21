FROM python:3.11-slim

LABEL maintainer="stig-ai-lab"
LABEL role="orchestrator"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.orchestrator.txt .
RUN pip install --no-cache-dir -r requirements.orchestrator.txt

COPY orchestrator.py .

ENV PYTHONUNBUFFERED=1
ENV SCANNER_URL=http://scanner:8001
ENV ANALYST_URL=http://analyst:8002
ENV REMEDIATION_URL=http://remediation:8003
ENV COMPLIANCE_URL=http://compliance:8004

ENTRYPOINT ["python3", "orchestrator.py"]
