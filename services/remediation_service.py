"""
services/remediation_service.py
FastAPI microservice — Remediation Agent
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
import ollama as ollama_client

import sys
sys.path.insert(0, "/app")
from agents.remediation_agent import build_remediation_prompt, build_validation_prompt
from tools.remediator import STIGRemediator
from tools.scanner import STIGFinding

app = FastAPI(title="STIG Remediation Agent", version="1.0.0")

OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",    "llama3.1")
PLAYBOOKS_DIR = os.getenv("PLAYBOOKS_DIR",   "/playbooks")
DRY_RUN       = os.getenv("DRY_RUN",         "false").lower() == "true"

remediator = STIGRemediator(PLAYBOOKS_DIR, dry_run=DRY_RUN)


class FindingInput(BaseModel):
    rule_id:     str
    title:       str
    severity:    str
    description: str
    fix_text:    str
    check_text:  Optional[str] = ""
    result:      Optional[str] = "fail"

class PlaybookResponse(BaseModel):
    rule_id:       str
    playbook_yaml: str

class ApplyRequest(BaseModel):
    finding:       FindingInput
    playbook_yaml: str
    confirmed:     bool = False

class ApplyResponse(BaseModel):
    rule_id: str
    success: bool
    output:  str
    dry_run: bool


def _ask(prompt: str) -> str:
    try:
        r = ollama_client.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
        )
        return r["message"]["content"]
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"LLM error: {e}")


def _to_finding(f: FindingInput) -> STIGFinding:
    return STIGFinding(
        rule_id=f.rule_id, title=f.title, severity=f.severity,
        result=f.result or "fail", description=f.description,
        fix_text=f.fix_text, check_text=f.check_text or "",
    )


@app.get("/health")
async def health():
    try:
        ollama_client.list()
        llm_ok = True
    except Exception:
        llm_ok = False
    return {"status": "healthy" if llm_ok else "degraded",
            "llm": llm_ok, "dry_run": DRY_RUN}


@app.post("/generate", response_model=PlaybookResponse)
async def generate_playbook(finding: FindingInput):
    f        = _to_finding(finding)
    prompt   = build_remediation_prompt(f)
    raw_yaml = _ask(prompt)

    clean_yaml = raw_yaml.strip()
    if clean_yaml.startswith("```"):
        lines = clean_yaml.split("\n")
        clean_yaml = "\n".join(
            l for l in lines if not l.strip().startswith("```")
        ).strip()

    return PlaybookResponse(rule_id=finding.rule_id, playbook_yaml=clean_yaml)


@app.post("/apply", response_model=ApplyResponse)
async def apply_remediation(req: ApplyRequest):
    if not req.confirmed:
        raise HTTPException(
            status_code=400,
            detail="confirmed must be true to apply remediations.",
        )
    f             = _to_finding(req.finding)
    playbook_path = remediator.generate_playbook(f, req.playbook_yaml)
    success, out  = remediator.apply_playbook(playbook_path)

    if success:
        remediator.record_applied(f.rule_id)
    else:
        remediator.record_failed(f.rule_id)

    return ApplyResponse(rule_id=f.rule_id, success=success,
                         output=out[-2000:], dry_run=DRY_RUN)


@app.get("/summary")
async def get_session_summary():
    return remediator.get_summary()


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8003, log_level="info")
