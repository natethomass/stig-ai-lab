"""
services/scanner_service.py
FastAPI microservice — Scanner Agent
"""

import os
import asyncio
import uuid
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from typing import Optional
import uvicorn

import sys
sys.path.insert(0, "/app")
from tools.scanner import OpenSCAPScanner, STIGFinding
from agents.scanner_agent import generate_scan_summary

app = FastAPI(title="STIG Scanner Agent", version="1.0.0")

_jobs: dict[str, dict] = {}

SCAP_CONTENT = os.getenv("SCAP_CONTENT_PATH", "/scap/ssg-rhel9-ds.xml")
STIG_PROFILE = os.getenv("STIG_PROFILE",      "stig")
REPORTS_DIR  = os.getenv("REPORTS_DIR",        "/reports")
MIN_SEVERITY = os.getenv("MIN_SEVERITY",        "CAT_II")


class ScanRequest(BaseModel):
    profile:      Optional[str] = None
    min_severity: Optional[str] = None
    results_xml:  Optional[str] = None

class ScanJob(BaseModel):
    job_id: str
    status: str
    message: str

class FindingModel(BaseModel):
    rule_id:     str
    title:       str
    severity:    str
    result:      str
    description: str
    fix_text:    str

class ScanResult(BaseModel):
    job_id:       str
    status:       str
    score:        Optional[dict]     = None
    findings:     list[FindingModel] = []
    summary:      Optional[str]      = None
    results_xml:  Optional[str]      = None
    report_html:  Optional[str]      = None
    error:        Optional[str]      = None


async def _run_scan(job_id: str, req: ScanRequest):
    _jobs[job_id]["status"] = "running"
    profile      = req.profile      or STIG_PROFILE
    min_severity = req.min_severity or MIN_SEVERITY
    scanner = OpenSCAPScanner(SCAP_CONTENT, profile, REPORTS_DIR)

    try:
        if req.results_xml:
            results_xml = req.results_xml
            report_html = None
        else:
            loop = asyncio.get_event_loop()
            results_xml, report_html = await loop.run_in_executor(
                None, scanner.run_scan)

        if not results_xml:
            _jobs[job_id]["status"] = "error"
            _jobs[job_id]["error"]  = "Scan failed — check oscap logs"
            return

        findings = scanner.parse_results(results_xml, min_severity)
        score    = scanner.get_compliance_score(results_xml)
        summary  = generate_scan_summary(findings, score)

        _jobs[job_id].update({
            "status":      "complete",
            "score":       score,
            "findings":    [_f(f) for f in findings],
            "summary":     summary,
            "results_xml": results_xml,
            "report_html": report_html,
        })

    except Exception as e:
        _jobs[job_id]["status"] = "error"
        _jobs[job_id]["error"]  = str(e)


def _f(f: STIGFinding) -> dict:
    return {
        "rule_id":     f.rule_id,
        "title":       f.title,
        "severity":    f.severity,
        "result":      f.result,
        "description": f.description,
        "fix_text":    f.fix_text,
    }


@app.get("/health")
async def health():
    import subprocess
    oscap_ok = subprocess.run(["which", "oscap"], capture_output=True).returncode == 0
    scap_ok  = os.path.exists(SCAP_CONTENT)
    return {
        "status":       "healthy" if (oscap_ok and scap_ok) else "degraded",
        "oscap":        oscap_ok,
        "scap_content": scap_ok,
    }


@app.post("/scan", response_model=ScanJob, status_code=202)
async def start_scan(req: ScanRequest, background_tasks: BackgroundTasks):
    job_id = str(uuid.uuid4())
    _jobs[job_id] = {"status": "queued", "job_id": job_id}
    background_tasks.add_task(_run_scan, job_id, req)
    return ScanJob(job_id=job_id, status="queued", message="Scan started")


@app.get("/scan/{job_id}", response_model=ScanResult)
async def get_scan_result(job_id: str):
    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return ScanResult(
        job_id      = job_id,
        status      = job["status"],
        score       = job.get("score"),
        findings    = [FindingModel(**f) for f in job.get("findings", [])],
        summary     = job.get("summary"),
        results_xml = job.get("results_xml"),
        report_html = job.get("report_html"),
        error       = job.get("error"),
    )


@app.get("/jobs")
async def list_jobs():
    return [{"job_id": k, "status": v["status"]} for k, v in _jobs.items()]


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001, log_level="info")
