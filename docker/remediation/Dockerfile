FROM python:3.11-slim

LABEL maintainer="stig-ai-lab"
LABEL role="remediation-agent"

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        openssh-client \
        sshpass \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.remediation.txt .
RUN pip install --no-cache-dir -r requirements.remediation.txt

COPY tools/__init__.py              tools/
COPY tools/scanner.py               tools/
COPY tools/remediator.py            tools/
COPY agents/__init__.py             agents/
COPY agents/remediation_agent.py    agents/
COPY services/remediation_service.py .
COPY config/ansible.cfg             /etc/ansible/ansible.cfg

VOLUME ["/playbooks", "/host-ssh"]

ENV PYTHONUNBUFFERED=1
ENV OLLAMA_BASE_URL=http://ollama:11434
ENV OLLAMA_MODEL=llama3.1
ENV PLAYBOOKS_DIR=/playbooks
ENV ANSIBLE_HOST_KEY_CHECKING=False

EXPOSE 8003

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s \
    CMD curl -sf http://localhost:8003/health || exit 1

CMD ["python3", "remediation_service.py"]
