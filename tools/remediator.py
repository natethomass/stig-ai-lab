"""
tools/remediator.py
Generates and applies Ansible playbooks for STIG remediations.
Also supports direct bash execution for simple fixes.
"""

import os
import subprocess
import re
import yaml
from datetime import datetime
from rich.console import Console
from tools.scanner import STIGFinding

console = Console()


class STIGRemediator:
    def __init__(self, playbooks_dir: str, dry_run: bool = False):
        self.playbooks_dir = playbooks_dir
        self.dry_run = dry_run
        os.makedirs(playbooks_dir, exist_ok=True)
        self._applied: list[str] = []
        self._skipped: list[str] = []
        self._failed: list[str] = []

    # ------------------------------------------------------------------ #
    #  Ansible playbook generation                                         #
    # ------------------------------------------------------------------ #

    def generate_playbook(self, finding: STIGFinding, task_yaml: str) -> str:
        """
        Generate an Ansible playbook for a single finding.
        task_yaml is the raw YAML task dict produced by the Remediation Agent.
        Returns the path to the generated playbook.
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        safe_id   = re.sub(r"[^a-zA-Z0-9_-]", "_", finding.rule_id)
        filename  = f"remediate_{safe_id}_{timestamp}.yml"
        filepath  = os.path.join(self.playbooks_dir, filename)

        # Parse the task block provided by the LLM
        try:
            task_block = yaml.safe_load(task_yaml)
            if isinstance(task_block, dict):
                task_block = [task_block]
        except yaml.YAMLError:
            # Fallback: wrap raw fix_text in a shell task
            task_block = [{
                "name": f"Apply fix for {finding.rule_id}",
                "shell": finding.fix_text,
                "become": True,
            }]

        playbook = [{
            "name": f"STIG Remediation: {finding.rule_id}",
            "hosts": "localhost",
            "become": True,
            "gather_facts": True,
            "vars": {
                "stig_rule_id":  finding.rule_id,
                "stig_severity": finding.severity,
            },
            "tasks": task_block,
            "post_tasks": [{
                "name": "Log remediation",
                "lineinfile": {
                    "path":   "/var/log/stig_remediation.log",
                    "line":   f"{{{{ ansible_date_time.iso8601 }}}} APPLIED {finding.rule_id} [{finding.severity}]",
                    "create": True,
                },
            }],
        }]

        with open(filepath, "w") as f:
            yaml.dump(playbook, f, default_flow_style=False, sort_keys=False)

        return filepath

    def apply_playbook(self, playbook_path: str) -> tuple[bool, str]:
        """
        Run ansible-playbook. Returns (success, output).
        In dry_run mode, adds --check flag (no changes made).
        """
        cmd = ["ansible-playbook", playbook_path, "-v"]
        if self.dry_run:
            cmd.append("--check")
            console.print("[yellow]DRY RUN MODE — no changes will be applied[/yellow]")

        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120
            )
            success = result.returncode == 0
            output  = result.stdout + result.stderr
            return success, output
        except FileNotFoundError:
            return False, "ansible-playbook not found. Install with: sudo dnf install ansible"
        except subprocess.TimeoutExpired:
            return False, "Playbook execution timed out after 120 seconds"

    # ------------------------------------------------------------------ #
    #  Direct bash execution (fallback for simple fixes)                   #
    # ------------------------------------------------------------------ #

    def apply_bash_fix(self, finding: STIGFinding, bash_commands: str) -> tuple[bool, str]:
        """
        Execute bash commands directly. Used when Ansible is overkill
        for a simple one-liner fix.
        """
        if self.dry_run:
            console.print(f"[yellow]DRY RUN — would execute:[/yellow]\n{bash_commands}")
            return True, "dry-run"

        try:
            result = subprocess.run(
                bash_commands, shell=True, capture_output=True,
                text=True, timeout=60
            )
            return result.returncode == 0, result.stdout + result.stderr
        except subprocess.TimeoutExpired:
            return False, "Command timed out"

    # ------------------------------------------------------------------ #
    #  Tracking                                                            #
    # ------------------------------------------------------------------ #

    def record_applied(self, rule_id: str):
        self._applied.append(rule_id)

    def record_skipped(self, rule_id: str):
        self._skipped.append(rule_id)

    def record_failed(self, rule_id: str):
        self._failed.append(rule_id)

    def get_summary(self) -> dict:
        return {
            "applied": self._applied,
            "skipped": self._skipped,
            "failed":  self._failed,
            "total_applied": len(self._applied),
            "total_skipped": len(self._skipped),
            "total_failed":  len(self._failed),
        }

    def save_session_log(self, reports_dir: str):
        """Write a session summary log."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_path  = os.path.join(reports_dir, f"session_log_{timestamp}.txt")
        summary   = self.get_summary()

        with open(log_path, "w") as f:
            f.write(f"STIG Hardening Session — {datetime.now().isoformat()}\n")
            f.write("=" * 60 + "\n\n")
            f.write(f"Applied  ({summary['total_applied']}): {', '.join(summary['applied']) or 'none'}\n")
            f.write(f"Skipped  ({summary['total_skipped']}): {', '.join(summary['skipped']) or 'none'}\n")
            f.write(f"Failed   ({summary['total_failed']}): {', '.join(summary['failed']) or 'none'}\n")

        console.print(f"\n[dim]Session log saved: {log_path}[/dim]")
        return log_path
