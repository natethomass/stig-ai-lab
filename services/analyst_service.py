"""
services/analyst_service.py
FastAPI microservice — Analyst Agent
"""

import os
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import uvicorn
import ollama as ollama_client

import sys
sys.path.insert(0, "/app")
from agents.analyst_agent import build_analysis_prompt, build_batch_analysis_prompt
from tools.scanner import STIGFinding

app = FastAPI(title="STIG Analyst Agent", version="1.0.0")

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL",    "llama3.1")
OLLAMA_URL   = os.getenv("OLLAMA_BASE_URL", "http://ollama:11434")


class FindingInput(BaseModel):
    rule_id:     str
    title:       str
    severity:    str
    description: str
    fix_text:    str
    check_text:  Optional[str] = ""
    result:      Optional[str] = "fail"

class AnalysisResponse(BaseModel):
    rule_id:  str
    analysis: str

class BatchAnalysisRequest(BaseModel):
    findings: list[FindingInput]

class BatchAnalysisResponse(BaseModel):
    triage_report: str
    finding_count: int


def _ask(prompt: str, system: str = None) -> str:
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    try:
        r = ollama_client.chat(model=OLLAMA_MODEL, messages=messages,
                               options={"temperature": 0.3})
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
            "llm": llm_ok, "model": OLLAMA_MODEL}


@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_finding(finding: FindingInput):
    f        = _to_finding(finding)
    prompt   = build_analysis_prompt(f)
    analysis = _ask(prompt,
                    system="You are a senior STIG security analyst. Be concise and direct.")
    return AnalysisResponse(rule_id=finding.rule_id, analysis=analysis)


@app.post("/analyze/batch", response_model=BatchAnalysisResponse)
async def analyze_batch(req: BatchAnalysisRequest):
    findings = [_to_finding(f) for f in req.findings]
    prompt   = build_batch_analysis_prompt(findings)
    report   = _ask(prompt,
                    system="You are a senior STIG security analyst. Be concise and direct.")
    return BatchAnalysisResponse(triage_report=report, finding_count=len(findings))


@app.post("/analyze/summarize")
async def summarize_finding(finding: FindingInput):
    prompt = (f"Summarize this STIG finding in ONE sentence (max 20 words):\n"
              f"Rule: {finding.rule_id}\nTitle: {finding.title}\n"
              f"Description: {finding.description[:300]}")
    summary = _ask(prompt)
    return {"rule_id": finding.rule_id, "summary": summary.strip()}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
