"""
agents/compliance_agent.py
CrewAI Compliance Agent — validates that remediations were successful,
tracks score improvements, and generates the final compliance report.
"""

from crewai import Agent
from langchain_community.llms import Ollama
from tools.scanner import STIGFinding, OpenSCAPScanner
from rich.console import Console
from rich.panel import Panel
from datetime import datetime
import json
import os

console = Console()


def build_compliance_agent(ollama_model: str, ollama_url: str) -> Agent:
    """Build and return the Compliance Agent."""

    llm = Ollama(
        model=ollama_model,
        base_url=ollama_url,
        temperature=0.2,
    )

    return Agent(
        role="STIG Compliance Officer",
        goal=(
            "Validate that STIG remediations were successfully applied, track compliance "
            "score improvements, identify any regressions, and generate comprehensive "
            "compliance reports suitable for submission to security teams or auditors."
        ),
        backstory=(
            "You are a compliance officer and information systems security officer (ISSO) "
            "responsible for maintaining an accurate picture of system security posture. "
            "You understand that compliance is a journey, not a destination, and help teams "
            "track progress, document decisions, and maintain audit trails. Your reports "
            "are clear, accurate, and stand up to scrutiny."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )


class ComplianceTracker:
    """Tracks compliance state across scan iterations."""

    def __init__(self, reports_dir: str):
        self.reports_dir = reports_dir
        self.history_file = os.path.join(reports_dir, "compliance_history.json")
        self._load_history()

    def _load_history(self):
        if os.path.exists(self.history_file):
            with open(self.history_file) as f:
                self.history = json.load(f)
        else:
            self.history = []

    def record_scan(self, score: dict, findings: list[STIGFinding], applied: list[str]):
        """Record a scan result to history."""
        entry = {
            "timestamp":   datetime.now().isoformat(),
            "score":       score.get("score", 0),
            "fail_count":  score.get("fail", 0),
            "pass_count":  score.get("pass", 0),
            "cat1_fails":  len([f for f in findings if f.severity == "CAT I"]),
            "cat2_fails":  len([f for f in findings if f.severity == "CAT II"]),
            "cat3_fails":  len([f for f in findings if f.severity == "CAT III"]),
            "applied_fixes": applied,
        }
        self.history.append(entry)

        with open(self.history_file, "w") as f:
            json.dump(self.history, f, indent=2)

        return entry

    def get_improvement(self) -> dict:
        """Calculate improvement between first and last scan."""
        if len(self.history) < 2:
            return {}
        first = self.history[0]
        last  = self.history[-1]
        return {
            "score_delta":     round(last["score"] - first["score"], 1),
            "failures_fixed":  first["fail_count"] - last["fail_count"],
            "first_score":     first["score"],
            "last_score":      last["score"],
            "scan_count":      len(self.history),
        }

    def print_progress(self):
        """Display compliance progress panel."""
        if not self.history:
            return

        improvement = self.get_improvement()
        latest = self.history[-1]

        if improvement:
            delta_str = f"+{improvement['score_delta']}%" if improvement['score_delta'] >= 0 else f"{improvement['score_delta']}%"
            color = "green" if improvement['score_delta'] >= 0 else "red"
            console.print(Panel(
                f"[bold]Compliance Score:[/bold] {latest['score']}% ([{color}]{delta_str}[/{color}] from baseline)\n"
                f"[bold]Failures Remaining:[/bold] {latest['fail_count']} "
                f"([green]-{improvement['failures_fixed']} fixed[/green])\n"
                f"[bold]CAT I Remaining:[/bold] {latest['cat1_fails']}\n"
                f"[bold]CAT II Remaining:[/bold] {latest['cat2_fails']}\n"
                f"[bold]CAT III Remaining:[/bold] {latest['cat3_fails']}",
                title="[bold cyan]Compliance Status[/bold cyan]",
                border_style="cyan",
            ))
        else:
            console.print(Panel(
                f"[bold]Compliance Score:[/bold] {latest['score']}%\n"
                f"[bold]Failures:[/bold] {latest['fail_count']}\n"
                f"[bold]CAT I:[/bold] {latest['cat1_fails']} | "
                f"[bold]CAT II:[/bold] {latest['cat2_fails']} | "
                f"[bold]CAT III:[/bold] {latest['cat3_fails']}",
                title="[bold cyan]Initial Compliance Baseline[/bold cyan]",
                border_style="cyan",
            ))


def build_final_report_prompt(
    before_score: dict,
    after_score: dict,
    applied: list[str],
    skipped: list[str],
    failed: list[str],
    remaining_findings: list[STIGFinding],
) -> str:
    """Prompt to generate an executive summary of the hardening session."""
    return f"""
Generate a concise executive summary of a STIG hardening session on RHEL 9.

BEFORE:
- Compliance Score  : {before_score.get('score', 0)}%
- Failed Controls   : {before_score.get('fail', 0)}

AFTER:
- Compliance Score  : {after_score.get('score', 0)}%
- Failed Controls   : {after_score.get('fail', 0)}

ACTIONS TAKEN:
- Applied  : {len(applied)} fixes ({', '.join(applied[:5])}{'...' if len(applied) > 5 else ''})
- Skipped  : {len(skipped)} (user declined)
- Failed   : {len(failed)} (errors during application)

REMAINING HIGH-PRIORITY FINDINGS:
{chr(10).join(f'- [{f.severity}] {f.rule_id}: {f.title}' for f in remaining_findings[:10])}

Write a 3-4 paragraph executive summary suitable for a security manager or auditor.
Include: what was accomplished, what remains, and recommended next steps.
"""
