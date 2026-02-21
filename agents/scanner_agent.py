"""
agents/scanner_agent.py
CrewAI Scanner Agent — responsible for running OpenSCAP scans
and delivering structured findings to the crew.
"""

from tools.scanner import STIGFinding


def generate_scan_summary(findings: list, score: dict) -> str:
    """Generate a plain-text summary of scan results."""
    cat1 = [f for f in findings if f.severity == "CAT I"]
    cat2 = [f for f in findings if f.severity == "CAT II"]
    cat3 = [f for f in findings if f.severity == "CAT III"]

    summary = (
        f"STIG Scan Complete\n"
        f"Compliance Score: {score.get('score', 0):.1f}%\n"
        f"Pass: {score.get('pass', 0)} | Fail: {score.get('fail', 0)}\n\n"
        f"Failures by severity:\n"
        f"  CAT I  (Critical): {len(cat1)}\n"
        f"  CAT II (High):     {len(cat2)}\n"
        f"  CAT III (Medium):  {len(cat3)}\n"
    )
    return summary


def build_scanner_agent(ollama_model: str = "llama3.1",
                        ollama_url: str = "http://localhost:11434"):
    """Placeholder — returns None in microservice mode."""
    return None

def generate_scan_summary(findings: list[STIGFinding], score: dict) -> str:
    """Generate a text summary suitable for passing to other agents."""
    cat1 = [f for f in findings if f.severity == "CAT I"]
    cat2 = [f for f in findings if f.severity == "CAT II"]
    cat3 = [f for f in findings if f.severity == "CAT III"]

    lines = [
        f"STIG SCAN SUMMARY",
        f"==================",
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
