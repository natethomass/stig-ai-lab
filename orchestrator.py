#!/usr/bin/env python3
"""
orchestrator.py — Distributed Orchestrator
Coordinates all agent microservices via HTTP.
Provides human-in-the-loop approval at each remediation step.

Usage:
  python3 orchestrator.py
  python3 orchestrator.py --dry-run
  python3 orchestrator.py --scan-only
"""

import os
import sys
import time
import argparse
import requests
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

console = Console()

SCANNER_URL     = os.getenv("SCANNER_URL",     "http://scanner:8001")
ANALYST_URL     = os.getenv("ANALYST_URL",     "http://analyst:8002")
REMEDIATION_URL = os.getenv("REMEDIATION_URL", "http://remediation:8003")
COMPLIANCE_URL  = os.getenv("COMPLIANCE_URL",  "http://compliance:8004")
DRY_RUN         = os.getenv("DRY_RUN", "false").lower() == "true"


def _post(url, data, timeout=360):
    r = requests.post(url, json=data, timeout=timeout)
    r.raise_for_status()
    return r.json()

def _get(url, timeout=30):
    r = requests.get(url, timeout=timeout)
    r.raise_for_status()
    return r.json()


def check_services():
    services = {
        "Scanner":     f"{SCANNER_URL}/health",
        "Analyst":     f"{ANALYST_URL}/health",
        "Remediation": f"{REMEDIATION_URL}/health",
        "Compliance":  f"{COMPLIANCE_URL}/health",
    }
    all_ok = True
    for name, url in services.items():
        try:
            r = requests.get(url, timeout=5)
            status = r.json().get("status", "unknown")
            icon   = "✓" if status == "healthy" else "⚠"
            color  = "green" if status == "healthy" else "yellow"
            console.print(f"  [{color}]{icon}[/{color}] {name}: {status}")
        except Exception as e:
            console.print(f"  [red]✗[/red] {name}: unreachable ({e})")
            all_ok = False
    return all_ok


def poll_scan(job_id, timeout_secs=600):
    deadline = time.time() + timeout_secs
    with Progress(SpinnerColumn(), TextColumn("{task.description}")) as progress:
        task = progress.add_task("Running OpenSCAP scan...", total=None)
        while time.time() < deadline:
            result = _get(f"{SCANNER_URL}/scan/{job_id}")
            if result["status"] == "complete":
                progress.update(task, description="✓ Scan complete")
                return result
            elif result["status"] == "error":
                raise RuntimeError(f"Scan failed: {result.get('error')}")
            time.sleep(5)
    raise TimeoutError("Scan timed out")


def print_findings_table(findings, score):
    console.print(
        f"\n[bold]Compliance Score: "
        f"[{'green' if score.get('score', 0) >= 70 else 'red'}]{score.get('score', 0)}%[/][/bold]  "
        f"Pass: {score.get('pass', 0)} | Fail: {score.get('fail', 0)}\n"
    )
    table = Table(title=f"Failed STIG Controls ({len(findings)})", show_lines=True)
    table.add_column("#",       style="dim",  width=4)
    table.add_column("Rule ID", style="cyan", width=30)
    table.add_column("Sev",     width=9)
    table.add_column("Title",   width=50)

    styles = {"CAT I": "red", "CAT II": "yellow", "CAT III": "blue"}
    for i, f in enumerate(findings, 1):
        s = styles.get(f["severity"], "white")
        table.add_row(str(i), f["rule_id"],
                      f"[{s}]{f['severity']}[/{s}]", f["title"][:50])
    console.print(table)


def present_for_approval(finding, analysis, playbook, num, total):
    sev_color = {"CAT I": "red", "CAT II": "yellow", "CAT III": "blue"}.get(
        finding["severity"], "white")
    console.print(f"\n{'═' * 70}")
    console.print(
        f"[bold]Finding {num}/{total}[/bold]  "
        f"[{sev_color}]{finding['severity']}[/{sev_color}]  {finding['rule_id']}")
    console.print(f"[bold cyan]{finding['title']}[/bold cyan]")
    console.print(f"{'─' * 70}")
    console.print(Panel(analysis, title="[bold]AI Analysis[/bold]",
                        border_style="blue"))
    console.print(Panel(playbook, title="[bold]Proposed Ansible Task[/bold]",
                        border_style="green"))

    while True:
        choice = Prompt.ask(
            "\n[bold]Action[/bold]",
            choices=["apply", "skip", "quit", "a", "s", "q"],
            default="skip",
        ).lower()
        if choice in ("apply", "a"): return "apply"
        if choice in ("skip",  "s"): return "skip"
        if choice in ("quit",  "q"): return "quit"


def run(args):
    console.print(Panel(
        f"[bold cyan]STIG AI Hardening Lab — Distributed Mode[/bold cyan]\n"
        f"Scanner:     {SCANNER_URL}\n"
        f"Analyst:     {ANALYST_URL}\n"
        f"Remediation: {REMEDIATION_URL}\n"
        f"Compliance:  {COMPLIANCE_URL}\n"
        f"Dry Run:     {args.dry_run or DRY_RUN}",
        title="[bold]Configuration[/bold]",
    ))

    console.rule("[bold]Service Health[/bold]")
    if not check_services():
        console.print("[red]One or more services unreachable. Check docker compose logs.[/red]")
        if not Confirm.ask("Continue anyway?", default=False):
            sys.exit(1)

    # ── PHASE 1: Scan ────────────────────────────────────────────────────
    console.rule("[bold cyan]PHASE 1: Scanning[/bold cyan]")
    scan_req = {}
    if args.results:
        scan_req["results_xml"] = args.results

    job    = _post(f"{SCANNER_URL}/scan", scan_req)
    result = poll_scan(job["job_id"])

    findings     = result["findings"]
    score        = result["score"]
    before_score = score

    if not findings:
        console.print("[green]No failures found at configured severity level![/green]")
        sys.exit(0)

    print_findings_table(findings, score)

    _post(f"{COMPLIANCE_URL}/record", {
        "score":    {"score": score["score"],
                     "pass_count": score["pass"],
                     "fail_count": score["fail"]},
        "findings": findings,
        "applied":  [],
    })

    if args.scan_only:
        console.print("[yellow]--scan-only mode. Done.[/yellow]")
        sys.exit(0)

    # ── PHASE 2: Batch triage ────────────────────────────────────────────
    console.rule("[bold cyan]PHASE 2: AI Triage Analysis[/bold cyan]")
    with Progress(SpinnerColumn(), TextColumn("Analyzing all findings...")) as p:
        t = p.add_task("", total=None)
        triage = _post(f"{ANALYST_URL}/analyze/batch",
                       {"findings": findings}, timeout=180)
        p.update(t, completed=True)

    console.print(Panel(triage["triage_report"],
                        title="[bold]AI Triage Report[/bold]",
                        border_style="cyan"))

    if not Confirm.ask("\nProceed to remediation?", default=True):
        console.print("[yellow]Exiting. No changes made.[/yellow]")
        sys.exit(0)

    # ── PHASE 3: Per-finding remediation loop ────────────────────────────
    console.rule("[bold cyan]PHASE 3: Interactive Remediation[/bold cyan]")

    applied, skipped, failed = [], [], []

    for i, finding in enumerate(findings, 1):
        with Progress(SpinnerColumn(),
                      TextColumn(f"Analyzing {finding['rule_id']}...")) as p:
            t = p.add_task("", total=None)
            analysis_resp = _post(f"{ANALYST_URL}/analyze",      finding, timeout=120)
            playbook_resp = _post(f"{REMEDIATION_URL}/generate", finding, timeout=120)
            p.update(t, completed=True)

        decision = present_for_approval(
            finding,
            analysis_resp["analysis"],
            playbook_resp["playbook_yaml"],
            i, len(findings),
        )

        if decision == "quit":
            console.print("\n[yellow]Exiting remediation loop.[/yellow]")
            break
        elif decision == "skip":
            skipped.append(finding["rule_id"])
            console.print(f"[dim]Skipped {finding['rule_id']}[/dim]")
            continue
        elif decision == "apply":
            apply_resp = _post(f"{REMEDIATION_URL}/apply", {
                "finding":       finding,
                "playbook_yaml": playbook_resp["playbook_yaml"],
                "confirmed":     True,
            }, timeout=120)

            if apply_resp["success"]:
                applied.append(finding["rule_id"])
                console.print(f"[green]✓ Applied {finding['rule_id']}[/green]")
            else:
                failed.append(finding["rule_id"])
                console.print(f"[red]✗ Failed {finding['rule_id']}[/red]")
                console.print(f"[dim]{apply_resp['output'][-300:]}[/dim]")

    # ── PHASE 4: Final report ────────────────────────────────────────────
    if applied and not (args.dry_run or DRY_RUN):
        console.rule("[bold cyan]PHASE 4: Final Report[/bold cyan]")
        if Confirm.ask("Generate final compliance report?", default=True):
            job2    = _post(f"{SCANNER_URL}/scan", {})
            result2 = poll_scan(job2["job_id"])
            after_score = result2["score"]

            _post(f"{COMPLIANCE_URL}/record", {
                "score":    {"score": after_score["score"],
                             "pass_count": after_score["pass"],
                             "fail_count": after_score["fail"]},
                "findings": result2["findings"],
                "applied":  applied,
            })

            print_findings_table(result2["findings"], after_score)

            report = _post(f"{COMPLIANCE_URL}/report/final", {
                "before_score": {"score": before_score["score"],
                                 "pass_count": before_score["pass"],
                                 "fail_count": before_score["fail"]},
                "after_score":  {"score": after_score["score"],
                                 "pass_count": after_score["pass"],
                                 "fail_count": after_score["fail"]},
                "applied":            applied,
                "skipped":            skipped,
                "failed":             failed,
                "remaining_findings": result2["findings"][:10],
            }, timeout=120)

            console.print(Panel(report["report"],
                                title="[bold]Executive Summary[/bold]",
                                border_style="green"))

    console.print(Panel(
        f"Applied : [green]{len(applied)}[/green]\n"
        f"Skipped : [yellow]{len(skipped)}[/yellow]\n"
        f"Failed  : [red]{len(failed)}[/red]",
        title="[bold]Session Complete[/bold]",
        border_style="bold green",
    ))


def main():
    parser = argparse.ArgumentParser(
        description="STIG AI Lab — Distributed Orchestrator")
    parser.add_argument("--dry-run",   action="store_true")
    parser.add_argument("--scan-only", action="store_true")
    parser.add_argument("--results",   type=str)
    args = parser.parse_args()
    run(args)


if __name__ == "__main__":
    main()
