FROM registry.access.redhat.com/ubi9/ubi:latest

LABEL maintainer="stig-ai-lab"
LABEL role="scanner-agent"

RUN dnf install -y \
        python3 \
        python3-pip \
        openscap-scanner \
        xmlstarlet \
        curl \
    && dnf clean all \
    && rm -rf /var/cache/dnf

WORKDIR /app
COPY requirements.scanner.txt .
RUN pip3 install --no-cache-dir -r requirements.scanner.txt

COPY tools/__init__.py       tools/
COPY tools/scanner.py        tools/
COPY agents/__init__.py      agents/
COPY agents/scanner_agent.py agents/
COPY services/scanner_service.py .

VOLUME ["/scap", "/reports"]

ENV SCAP_CONTENT_PATH=/scap/ssg-rhel9-ds.xml
ENV REPORTS_DIR=/reports
ENV PYTHONUNBUFFERED=1

EXPOSE 8001

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s \
    CMD curl -sf http://localhost:8001/health || exit 1

CMD ["python3", "scanner_service.py"]
