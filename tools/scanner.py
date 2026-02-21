"""
tools/scanner.py
Wraps OpenSCAP (oscap) to run STIG compliance scans and parse results.
"""

import subprocess
import os
import xml.etree.ElementTree as ET
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional
from rich.console import Console

console = Console()

# XCCDF XML namespaces
NS = {
    "xccdf": "http://checklists.nist.gov/xccdf/1.2",
    "dc":    "http://purl.org/dc/elements/1.1/",
}

SEVERITY_MAP = {
    "high":   "CAT I",
    "medium": "CAT II",
    "low":    "CAT III",
}

CAT_PRIORITY = {"CAT I": 3, "CAT II": 2, "CAT III": 1}


@dataclass
class STIGFinding:
    rule_id: str
    title: str
    severity: str          # CAT I / CAT II / CAT III
    result: str            # pass / fail / notchecked / notapplicable
    description: str
    fix_text: str
    check_text: str
    references: list[str] = field(default_factory=list)

    @property
    def cat_priority(self) -> int:
        return CAT_PRIORITY.get(self.severity, 0)

    def __str__(self):
        return f"[{self.severity}] {self.rule_id} — {self.title}"


class OpenSCAPScanner:
    def __init__(self, scap_content: str, profile: str, reports_dir: str):
        self.scap_content = scap_content
        self.profile = f"xccdf_org.ssgproject.content_profile_{profile}"
        self.reports_dir = reports_dir
        os.makedirs(reports_dir, exist_ok=True)

    def _check_prerequisites(self) -> bool:
        """Verify oscap is installed and SCAP content exists."""
        result = subprocess.run(["which", "oscap"], capture_output=True)
        if result.returncode != 0:
            console.print("[red]ERROR: oscap not found. Install with: sudo dnf install openscap-scanner scap-security-guide[/red]")
            return False
        if not os.path.exists(self.scap_content):
            console.print(f"[red]ERROR: SCAP content not found at {self.scap_content}[/red]")
            console.print("[yellow]Install with: sudo dnf install scap-security-guide[/yellow]")
            return False
        return True

    def run_scan(self) -> tuple[Optional[str], Optional[str]]:
        """
        Execute oscap scan. Returns (results_xml_path, report_html_path).
        Must be run as root for accurate results.
        """
        if not self._check_prerequisites():
            return None, None

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_xml  = os.path.join(self.reports_dir, f"scan_results_{timestamp}.xml")
        report_html  = os.path.join(self.reports_dir, f"scan_report_{timestamp}.html")

        cmd = [
            "oscap", "xccdf", "eval",
            "--profile",  self.profile,
            "--results",  results_xml,
            "--report",   report_html,
            "--oval-results",
            self.scap_content,
        ]

        console.print(f"\n[cyan]Running OpenSCAP scan with profile: {self.profile}[/cyan]")
        console.print("[dim]This may take several minutes...[/dim]\n")

        try:
            # oscap returns exit code 2 when there are failures (normal)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            if result.returncode not in (0, 2):
                console.print(f"[red]Scan failed:\n{result.stderr}[/red]")
                return None, None

            console.print(f"[green]✓ Scan complete[/green]")
            console.print(f"  Results XML : {results_xml}")
            console.print(f"  Report HTML : {report_html}")
            return results_xml, report_html

        except subprocess.TimeoutExpired:
            console.print("[red]ERROR: Scan timed out after 10 minutes[/red]")
            return None, None
        except FileNotFoundError:
            console.print("[red]ERROR: oscap command not found[/red]")
            return None, None

    def parse_results(self, results_xml: str, min_severity: str = "CAT_II") -> list[STIGFinding]:
        """
        Parse the XCCDF results XML and return a list of failed findings
        filtered by minimum severity.
        """
        if not os.path.exists(results_xml):
            console.print(f"[red]Results file not found: {results_xml}[/red]")
            return []

        tree = ET.parse(results_xml)
        root = tree.getroot()

        # Build a map of rule definitions from the benchmark
        rule_defs = self._extract_rule_definitions(root)

        findings = []
        for rr in root.findall(".//xccdf:rule-result", NS):
            result_el = rr.find("xccdf:result", NS)
            if result_el is None or result_el.text != "fail":
                continue

            rule_id  = rr.get("idref", "unknown")
            rule_def = rule_defs.get(rule_id, {})

            severity_raw = rr.get("severity", rule_def.get("severity", "medium"))
            severity     = SEVERITY_MAP.get(severity_raw.lower(), "CAT II")

            # Filter by minimum severity
            if not self._meets_severity(severity, min_severity):
                continue

            finding = STIGFinding(
                rule_id     = rule_id,
                title       = rule_def.get("title", rule_id),
                severity    = severity,
                result      = "fail",
                description = rule_def.get("description", "No description available."),
                fix_text    = rule_def.get("fix_text", "No automated fix available."),
                check_text  = rule_def.get("check_text", ""),
                references  = rule_def.get("references", []),
            )
            findings.append(finding)

        # Sort: CAT I first, then II, then III
        findings.sort(key=lambda f: f.cat_priority, reverse=True)
        return findings

    def _extract_rule_definitions(self, root: ET.Element) -> dict:
        """Extract rule metadata from the benchmark section of the results file."""
        defs = {}
        for rule in root.findall(".//xccdf:Rule", NS):
            rule_id    = rule.get("id", "")
            title_el   = rule.find("xccdf:title", NS)
            desc_el    = rule.find("xccdf:description", NS)
            fix_el     = rule.find("xccdf:fixtext", NS)
            check_el   = rule.find(".//xccdf:check-content", NS)

            refs = [
                ref.text for ref in rule.findall("xccdf:reference", NS)
                if ref.text
            ]

            defs[rule_id] = {
                "severity":    rule.get("severity", "medium"),
                "title":       title_el.text  if title_el  else rule_id,
                "description": desc_el.text   if desc_el   else "",
                "fix_text":    fix_el.text    if fix_el    else "",
                "check_text":  check_el.text  if check_el  else "",
                "references":  refs,
            }
        return defs

    def _meets_severity(self, severity: str, min_severity: str) -> bool:
        min_map = {"CAT_I": 3, "CAT_II": 2, "CAT_III": 1, "ALL": 0}
        threshold = min_map.get(min_severity, 2)
        return CAT_PRIORITY.get(severity, 0) >= threshold

    def get_compliance_score(self, results_xml: str) -> dict:
        """Calculate overall compliance score from results XML."""
        if not os.path.exists(results_xml):
            return {}

        tree = ET.parse(results_xml)
        root = tree.getroot()

        counts = {"pass": 0, "fail": 0, "notchecked": 0, "notapplicable": 0, "error": 0}
        for rr in root.findall(".//xccdf:rule-result", NS):
            result_el = rr.find("xccdf:result", NS)
            if result_el is not None:
                counts[result_el.text] = counts.get(result_el.text, 0) + 1

        total_checked = counts["pass"] + counts["fail"]
        score = (counts["pass"] / total_checked * 100) if total_checked > 0 else 0

        return {
            "score":          round(score, 1),
            "pass":           counts["pass"],
            "fail":           counts["fail"],
            "notchecked":     counts["notchecked"],
            "notapplicable":  counts["notapplicable"],
            "total_checked":  total_checked,
        }
