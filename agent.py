#!/usr/bin/env python3
"""
agent.py — STIG AI Hardening Lab CLI
Works in two modes:
  1. LOCAL mode  — runs agents in-process (original behavior)
  2. DOCKER mode — talks to containerized microservices via REST API

Usage:
    # Local mode (original)
    sudo python agent.py

    # Docker mode (talks to running containers)
    python agent.py --docker

    # Docker mode with custom orchestrator URL
    python agent.py --docker --api http://192.168.1.100:80

    # Dry run
    python agent.py --docker --dry-run
"""

import os
import sys
import time
import argparse
import httpx
from dotenv import load_dotenv
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

load_dotenv()
console = Console()


# ======================================================================== #
#  Docker / API mode client                                                 #
# ======================================================================== #

class OrchestratorClient:
    """HTTP client for the containerized orchestrator service."""

    def __init__(self, base_url: str = "http://localhost:80"):
        self.base_url = base_url.rstrip("/")
        self.client   = httpx.Client(timeout=600.0)

    def health(self) -> dict:
        return self.client.get(f"{self.base_url}/health").json()

    def start_session(self, profile: str, min_severity: str, dry_run: bool,
                      auto_apply_cat3: bool = False) -> str:
        resp = self.client.post(f"{self.base_url}/session/start", json={
            "profile":         profile,
            "min_severity":    min_severity,
            "dry_run":         dry_run,
            "auto_apply_cat3": auto_apply_cat3,
        })
        resp.raise_for_status()
        return resp.json()["session_id"]

    def get_session(self, session_id: str) -> dict:
        return self.client.get(f"{self.base_url}/session/{session_id}").json()

    def get_pending(self, session_id: str):
        resp = self.client.get(f"{self.base_url}/session/{session_id}/pending")
        if resp.status_code == 200:
            return resp.json()
        return None

    def approve(self, session_id: str, rule_id: str, decision: str):
        self.client.post(f"{self.base_url}/session/{session_id}/approve", json={
            "session_id": session_id,
            "rule_id":    rule_id,
            "decision":   decision,
        })


# ======================================================================== #
#  Docker mode workflow                                                     #
# ======================================================================== #

def run_docker_mode(args):
    """Interact with the containerized agent stack via REST."""
    api_url = args.api or os.getenv("ORCHESTRATOR_URL", "http://localhost:80")
    client  = OrchestratorClient(api_url)

    console.print(Panel(
        f"[bold cyan]STIG AI Hardening Lab[/bold cyan] — [yellow]Docker Mode[/yellow]\n"
        f"API      : {api_url}\n"
        f"Profile  : {args.profile}\n"
        f"Min Sev  : {args.min_severity}\n"
        f"Dry Run  : {args.dry_run}",
        title="[bold]Configuration[/bold]",
    ))

    # ── Health check ─────────────────────────────────────────────────────
    console.print("\n[cyan]Checking service health...[/cyan]")
    try:
        health   = client.health()
        services = health.get("services", {})
        table    = Table(show_header=False, box=None)
        for svc, status in services.items():
            color = "green" if status == "ok" else "red"
            table.add_row(f"  {svc}", f"[{color}]{status}[/{color}]")
        console.print(table)
        if health.get("status") != "ok":
            if not Confirm.ask("[yellow]Some services are degraded. Continue?[/yellow]", default=False):
                sys.exit(1)
    except Exception as e:
        console.print(f"[red]Cannot reach orchestrator at {api_url}: {e}[/red]")
        console.print("[dim]Tip: Run 'docker compose up -d' first[/dim]")
        sys.exit(1)

    # ── Start session ─────────────────────────────────────────────────────
    console.print("\n[cyan]Starting hardening session...[/cyan]")
    session_id = client.start_session(
        profile         = args.profile,
        min_severity    = args.min_severity,
        dry_run         = args.dry_run,
        auto_apply_cat3 = getattr(args, "auto_cat3", False),
    )
    console.print(f"[green]Session ID: {session_id}[/green]")

    last_phase   = None
    last_pending = None

    while True:
        session = client.get_session(session_id)
        phase   = session.get("phase", "queued")

        if phase != last_phase:
            phase_labels = {
                "queued":      "[dim]Queued...[/dim]",
                "scanning":    "[cyan]Phase 1: Running OpenSCAP scan...[/cyan]",
                "analyzing":   "[cyan]Phase 2: AI triage analysis...[/cyan]",
                "remediating": "[cyan]Phase 3: Interactive remediation...[/cyan]",
                "validating":  "[cyan]Phase 4: Post-remediation validation...[/cyan]",
                "complete":    "[green]Complete![/green]",
                "error":       "[red]Error![/red]",
            }
            console.print(phase_labels.get(phase, phase))
            last_phase = phase

            if phase == "scanning":
                console.print("[dim]  This may take several minutes...[/dim]")
            if phase == "analyzing":
                score = session.get("score_before", "?")
                total = session.get("total_findings", "?")
                console.print(f"  Baseline score: [bold]{score}%[/bold] | Findings: [bold]{total}[/bold]")

        # ── Approval gate ─────────────────────────────────────────────────
        if phase == "remediating":
            pending = client.get_pending(session_id)
            if pending and pending != last_pending:
                last_pending = pending
                finding  = pending["finding"]
                analysis = pending.get("analysis", "No analysis available.")
                playbook = pending.get("playbook_yaml", "No playbook generated.")

                sev_color = {"CAT I": "red", "CAT II": "yellow", "CAT III": "blue"}.get(
                    finding.get("severity", ""), "white"
                )
                console.print(f"\n{'═' * 68}")
                console.print(
                    f"[bold]Finding[/bold]  [{sev_color}]{finding.get('severity')}[/{sev_color}]  "
                    f"{finding.get('rule_id')}"
                )
                console.print(f"[bold cyan]{finding.get('title', '')}[/bold cyan]")
                console.print(Panel(analysis, title="[bold]AI Analysis[/bold]",      border_style="blue"))
                console.print(Panel(playbook,  title="[bold]Proposed Ansible Task[/bold]", border_style="green"))

                choice = Prompt.ask(
                    "\n[bold]Action[/bold]",
                    choices=["apply", "skip", "a", "s"],
                    default="skip",
                ).lower()
                decision = "apply" if choice in ("apply", "a") else "skip"
                client.approve(session_id, finding["rule_id"], decision)

        if phase == "complete":
            _print_completion(session)
            break
        if phase == "error":
            console.print(f"[red]Session error: {session.get('error')}[/red]")
            sys.exit(1)

        time.sleep(2.0)


def _print_completion(session: dict):
    console.print(Panel(
        f"Applied : [green]{len(session.get('applied', []))}[/green]\n"
        f"Skipped : [yellow]{len(session.get('skipped', []))}[/yellow]\n"
        f"Failed  : [red]{len(session.get('failed', []))}[/red]\n\n"
        f"Score before : [bold]{session.get('score_before', '?')}%[/bold]\n"
        f"Score after  : [bold]{session.get('score_after', 'N/A')}%[/bold]",
        title="[bold green]Session Complete[/bold green]",
        border_style="green",
    ))


# ======================================================================== #
#  Local mode (original in-process workflow)                                #
# ======================================================================== #

def run_local_mode(args):
    """Original in-process mode — no Docker required."""
    from tools.scanner import OpenSCAPScanner
    from tools.remediator import STIGRemediator
    from agents.scanner_agent import print_findings_table, generate_scan_summary
    from agents.analyst_agent import build_analysis_prompt, build_batch_analysis_prompt
    from agents.remediation_agent import build_remediation_prompt
    from agents.compliance_agent import ComplianceTracker, build_final_report_prompt
    import ollama as ollama_client

    OLLAMA_MODEL  = os.getenv("OLLAMA_MODEL",     "llama3.1")
    OLLAMA_URL    = os.getenv("OLLAMA_BASE_URL",   "http://localhost:11434")
    SCAP_CONTENT  = os.getenv("SCAP_CONTENT_PATH", "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml")
    STIG_PROFILE  = args.profile or os.getenv("STIG_PROFILE", "stig")
    REPORTS_DIR   = os.getenv("REPORTS_DIR",   "./reports")
    PLAYBOOKS_DIR = os.getenv("PLAYBOOKS_DIR", "./playbooks")
    MIN_SEVERITY  = args.min_severity or os.getenv("MIN_SEVERITY", "CAT_II")

    def ask_llm(prompt, system=""):
        msgs = []
        if system:
            msgs.append({"role": "system", "content": system})
        msgs.append({"role": "user", "content": prompt})
        c = ollama_client.Client(host=OLLAMA_URL)
        return c.chat(model=OLLAMA_MODEL, messages=msgs)["message"]["content"]

    scanner    = OpenSCAPScanner(SCAP_CONTENT, STIG_PROFILE, REPORTS_DIR)
    remediator = STIGRemediator(PLAYBOOKS_DIR, dry_run=args.dry_run)
    tracker    = ComplianceTracker(REPORTS_DIR)

    console.print(Panel(
        f"[bold cyan]STIG AI Hardening Lab[/bold cyan] — [yellow]Local Mode[/yellow]\n"
        f"Model    : {OLLAMA_MODEL}\n"
        f"Profile  : {STIG_PROFILE}\n"
        f"Min Sev  : {MIN_SEVERITY}\n"
        f"Dry Run  : {args.dry_run}",
        title="[bold]Configuration[/bold]",
    ))

    results_xml = args.results
    if not results_xml:
        results_xml, _ = scanner.run_scan()
        if not results_xml:
            sys.exit(1)

    findings     = scanner.parse_results(results_xml, MIN_SEVERITY)
    before_score = scanner.get_compliance_score(results_xml)
    print_findings_table(findings, before_score)
    tracker.record_scan(before_score, findings, [])
    tracker.print_progress()

    if args.scan_only:
        sys.exit(0)

    with Progress(SpinnerColumn(), TextColumn("AI triage analysis...")) as p:
        t = p.add_task("", total=None)
        triage = ask_llm(build_batch_analysis_prompt(findings))
        p.update(t, completed=True)
    console.print(Panel(triage, title="[bold]AI Triage[/bold]", border_style="cyan"))

    if not Confirm.ask("Proceed to remediation?", default=True):
        sys.exit(0)

    for i, finding in enumerate(findings, 1):
        with Progress(SpinnerColumn(), TextColumn(f"Analyzing {finding.rule_id}...")) as p:
            t = p.add_task("", total=None)
            analysis = ask_llm(build_analysis_prompt(finding))
            proposed = ask_llm(build_remediation_prompt(finding))
            p.update(t, completed=True)

        sev_color = {"CAT I": "red", "CAT II": "yellow", "CAT III": "blue"}.get(finding.severity, "white")
        console.print(f"\n{'═' * 68}")
        console.print(f"[bold]Finding {i}/{len(findings)}[/bold]  [{sev_color}]{finding.severity}[/{sev_color}]  {finding.rule_id}")
        console.print(f"[bold cyan]{finding.title}[/bold cyan]")
        console.print(Panel(analysis, title="[bold]AI Analysis[/bold]",      border_style="blue"))
        console.print(Panel(proposed,  title="[bold]Proposed Ansible Task[/bold]", border_style="green"))

        choice = Prompt.ask(
            "\n[bold]Action[/bold]",
            choices=["apply","skip","quit","a","s","q"],
            default="skip",
        ).lower()
        if choice in ("quit", "q"):
            break
        elif choice in ("skip", "s"):
            remediator.record_skipped(finding.rule_id)
        elif choice in ("apply", "a"):
            path    = remediator.generate_playbook(finding, proposed)
            ok, out = remediator.apply_playbook(path)
            if ok:
                remediator.record_applied(finding.rule_id)
                console.print(f"[green]✓ Applied {finding.rule_id}[/green]")
            else:
                remediator.record_failed(finding.rule_id)
                console.print(f"[red]✗ Failed  {finding.rule_id}[/red]")

    summary = remediator.get_summary()
    remediator.save_session_log(REPORTS_DIR)
    _print_completion({
        "score_before": before_score.get("score"),
        "applied":      summary["applied"],
        "skipped":      summary["skipped"],
        "failed":       summary["failed"],
    })


# ======================================================================== #
#  Entry point                                                              #
# ======================================================================== #

def main():
    parser = argparse.ArgumentParser(
        description="STIG AI Hardening Lab — AI-assisted DISA STIG compliance for RHEL 9",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  sudo python agent.py                       Local mode, interactive
  sudo python agent.py --dry-run             Local mode, no changes
  python agent.py --docker                   Docker mode (containers must be running)
  python agent.py --docker --api http://host Docker mode, custom API URL
  sudo python agent.py --scan-only           Scan and report only
        """,
    )
    parser.add_argument("--docker",       action="store_true", help="Use containerized agents")
    parser.add_argument("--api",          type=str,            help="Orchestrator URL (docker mode)")
    parser.add_argument("--dry-run",      action="store_true", help="Show changes without applying")
    parser.add_argument("--scan-only",    action="store_true", help="Scan and report only")
    parser.add_argument("--results",      type=str,            help="Existing scan results XML (local mode)")
    parser.add_argument("--profile",      type=str,            default="stig",   help="SCAP profile")
    parser.add_argument("--min-severity", type=str,            default="CAT_II", help="CAT_I | CAT_II | CAT_III | ALL")
    parser.add_argument("--auto-cat3",    action="store_true", help="Auto-apply CAT III fixes")
    parser.add_argument("--model",        type=str,            help="Override Ollama model")

    args = parser.parse_args()

    if args.model:
        os.environ["OLLAMA_MODEL"] = args.model

    if args.docker:
        run_docker_mode(args)
    else:
        if os.geteuid() != 0 and not args.dry_run and not args.scan_only:
            console.print("[yellow]WARNING: Not running as root.[/yellow]")
            if not Confirm.ask("Continue?", default=False):
                sys.exit(1)
        run_local_mode(args)


if __name__ == "__main__":
    main()
