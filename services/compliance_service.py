"""
services/compliance_service.py
FastAPI microservice — Compliance Agent
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
import ollama as ollama_client

import sys
sys.path.insert(0, "/app")
from agents.compliance_agent import ComplianceTracker, build_final_report_prompt
from tools.scanner import STIGFinding

app = FastAPI(title="STIG Compliance Agent", version="1.0.0")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL",    "llama3.1")
REPORTS_DIR  = os.getenv("REPORTS_DIR",     "/reports")

tracker = ComplianceTracker(REPORTS_DIR)


class ScoreSnapshot(BaseModel):
    score:         float
    pass_count:    int
    fail_count:    int
    notchecked:    Optional[int] = 0
    notapplicable: Optional[int] = 0

class FindingInput(BaseModel):
    rule_id:     str
    title:       str
    severity:    str
    result:      Optional[str] = "fail"
    description: Optional[str] = ""
    fix_text:    Optional[str] = ""
    check_text:  Optional[str] = ""

class RecordScanRequest(BaseModel):
    score:    ScoreSnapshot
    findings: list[FindingInput]
    applied:  list[str] = []

class FinalReportRequest(BaseModel):
    before_score:       ScoreSnapshot
    after_score:        ScoreSnapshot
    applied:            list[str]
    skipped:            list[str]
    failed:             list[str]
    remaining_findings: list[FindingInput]


def _ask(prompt: str, system: str = None) -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        r = ollama_client.chat(model=OLLAMA_MODEL, messages=messages,
                               options={"temperature": 0.2})
        return r["message"]["content"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM error: {e}")


def _to_finding(f: FindingInput) -> STIGFinding:
    return STIGFinding(
        rule_id=f.rule_id, title=f.title, severity=f.severity,
        result=f.result or "fail", description=f.description or "",
        fix_text=f.fix_text or "", check_text=f.check_text or "",
    )


@app.get("/health")
async def health():
    try:
        ollama_client.list()
        llm_ok = True
    except Exception:
        llm_ok = False
    return {"status": "healthy" if llm_ok else "degraded", "llm": llm_ok}


@app.post("/record")
async def record_scan(req: RecordScanRequest):
    score_dict = {"score": req.score.score,
                  "pass":  req.score.pass_count,
                  "fail":  req.score.fail_count}
    findings = [_to_finding(f) for f in req.findings]
    entry    = tracker.record_scan(score_dict, findings, req.applied)
    return {"recorded": True, "entry": entry}


@app.get("/history")
async def get_history():
    return {"history": tracker.history}


@app.get("/improvement")
async def get_improvement():
    improvement = tracker.get_improvement()
    if not improvement:
        return {"message": "Need at least 2 scans to show improvement",
                "history_count": len(tracker.history)}
    return improvement


@app.post("/report/final")
async def generate_final_report(req: FinalReportRequest):
    remaining = [_to_finding(f) for f in req.remaining_findings[:10]]
    prompt = build_final_report_prompt(
        before_score = {"score": req.before_score.score,
                        "fail":  req.before_score.fail_count},
        after_score  = {"score": req.after_score.score,
                        "fail":  req.after_score.fail_count},
        applied      = req.applied,
        skipped      = req.skipped,
        failed       = req.failed,
        remaining_findings = remaining,
    )
    report = _ask(prompt,
                  system="You are a compliance officer writing for a security manager.")
    return {"report": report}


@app.get("/score/latest")
async def latest_score():
    if not tracker.history:
        return {"message": "No scans recorded yet"}
    return tracker.history[-1]


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8004, log_level="info")
