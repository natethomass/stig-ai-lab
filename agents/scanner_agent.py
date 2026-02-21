"""
agents/scanner_agent.py
Scanner agent helpers - microservice mode, no crewai dependency.
"""

from tools.scanner import STIGFinding


def generate_scan_summary(findings: list, score: dict) -> str:
    cat1 = [f for f in findings if f.severity == "CAT I"]
    cat2 = [f for f in findings if f.severity == "CAT II"]
    cat3 = [f for f in findings if f.severity == "CAT III"]
    lines = [
        "STIG SCAN SUMMARY",
        "==================",
        f"Compliance Score : {score.get('score', 0)}%",
        f"Total Failures   : {len(findings)}",
        f"  CAT I  (High)  : {len(cat1)}",
        f"  CAT II (Medium): {len(cat2)}",
        f"  CAT III (Low)  : {len(cat3)}",
        "",
        "FAILED CONTROLS:",
    ]
    for f in findings:
        lines.append(f"  [{f.severity}] {f.rule_id}")
        lines.append(f"    Title: {f.title}")
        lines.append(f"    Fix  : {f.fix_text[:200]}...")
        lines.append("")
    return "\n".join(lines)


def build_scanner_agent(ollama_model: str = "llama3.1",
                        ollama_url: str = "http://localhost:11434"):
    return None
