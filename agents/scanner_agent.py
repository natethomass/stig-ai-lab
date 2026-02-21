"""
agents/scanner_agent.py
CrewAI Scanner Agent — responsible for running OpenSCAP scans
and delivering structured findings to the crew.
"""

from crewai import Agent
from langchain_community.llms import Ollama
from tools.scanner import OpenSCAPScanner, STIGFinding
from rich.console import Console
from rich.table import Table

console = Console()


def build_scanner_agent(ollama_model: str, ollama_url: str) -> Agent:
    """Build and return the Scanner Agent."""

    llm = Ollama(
        model=ollama_model,
        base_url=ollama_url,
        temperature=0.1,    # Low temp — we want consistent, factual output
    )

    return Agent(
        role="STIG Compliance Scanner",
        goal=(
            "Run OpenSCAP compliance scans against RHEL systems using DISA STIG profiles. "
            "Parse the results accurately, categorize findings by severity (CAT I, II, III), "
            "and produce a clear structured report of all failed controls."
        ),
        backstory=(
            "You are a senior information assurance specialist with deep expertise in "
            "DISA STIGs, SCAP scanning, and NIST 800-53 controls. You have performed "
            "hundreds of system assessments and know how to quickly triage findings and "
            "communicate risk to both technical and non-technical audiences."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )


def print_findings_table(findings: list[STIGFinding], score: dict):
    """Pretty-print findings to the terminal using rich."""

    # Score summary
    console.print(f"\n[bold]Compliance Score: [{'green' if score.get('score', 0) >= 70 else 'red'}]{score.get('score', 0)}%[/]")
    console.print(f"Pass: {score.get('pass', 0)} | Fail: {score.get('fail', 0)} | "
                  f"Not Checked: {score.get('notchecked', 0)} | N/A: {score.get('notapplicable', 0)}\n")

    # Findings table
    table = Table(title=f"Failed STIG Controls ({len(findings)} findings)", show_lines=True)
    table.add_column("#",        style="dim",    width=4)
    table.add_column("Rule ID",  style="cyan",   width=28)
    table.add_column("Severity", style="bold",   width=10)
    table.add_column("Title",                    width=50)

    severity_styles = {"CAT I": "red", "CAT II": "yellow", "CAT III": "blue"}

    for i, f in enumerate(findings, 1):
        style = severity_styles.get(f.severity, "white")
        table.add_row(
            str(i),
            f.rule_id,
            f"[{style}]{f.severity}[/{style}]",
            f.title[:50],
        )

    console.print(table)


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
