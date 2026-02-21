"""
agents/remediation_agent.py
CrewAI Remediation Agent — generates Ansible tasks and bash commands
to fix STIG findings. Does NOT apply them — that requires user approval.
"""

from crewai import Agent
from langchain_community.llms import Ollama
from tools.scanner import STIGFinding


def build_remediation_agent(ollama_model: str, ollama_url: str) -> Agent:
    """Build and return the Remediation Agent."""

    llm = Ollama(
        model=ollama_model,
        base_url=ollama_url,
        temperature=0.1,    # Very low — we want precise, correct code
    )

    return Agent(
        role="STIG Remediation Engineer",
        goal=(
            "Generate precise, idempotent Ansible tasks to remediate STIG findings on RHEL 9. "
            "All generated tasks must be safe to run multiple times without side effects, "
            "use proper Ansible modules (not raw shell commands where possible), "
            "and include proper error handling."
        ),
        backstory=(
            "You are a senior Linux systems engineer and Ansible expert who specializes "
            "in security hardening automation. You have hardened hundreds of RHEL systems "
            "to DISA STIG compliance. You write clean, idempotent playbooks that follow "
            "Ansible best practices and always account for edge cases that could break "
            "production systems."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )


def build_remediation_prompt(finding: STIGFinding) -> str:
    """Build a prompt asking the agent to generate an Ansible task for a finding."""
    return f"""
Generate an Ansible task (or small set of tasks) to remediate the following DISA STIG finding on RHEL 9.

Rule ID    : {finding.rule_id}
Severity   : {finding.severity}
Title      : {finding.title}
Description: {finding.description}
DISA Fix Text:
{finding.fix_text}

REQUIREMENTS:
- Use proper Ansible modules (lineinfile, file, service, sysctl, user, etc.) — avoid shell/command modules unless absolutely necessary
- The task must be idempotent (safe to run multiple times)
- Include a 'name' field with a descriptive name referencing the rule ID
- Use 'become: true' where root is required
- If a service restart is needed, use a handler or notify pattern
- Handle RHEL 9 specifically (systemd, dnf, etc.)

OUTPUT FORMAT:
Return ONLY valid YAML for the task(s). Do not include playbook wrapper, just the task dict(s).
Do not include any explanation text outside the YAML.

Example format:
- name: "V-XXXXXX | Disable root SSH login"
  lineinfile:
    path: /etc/ssh/sshd_config
    regexp: '^PermitRootLogin'
    line: 'PermitRootLogin no'
    state: present
  become: true
  notify: restart sshd
"""


def build_validation_prompt(finding: STIGFinding, applied_task: str) -> str:
    """Build a prompt to validate a fix was applied correctly."""
    return f"""
A STIG remediation was applied for the following control:

Rule ID : {finding.rule_id}
Title   : {finding.title}

The following Ansible task was executed:
{applied_task}

Generate a brief bash command or Ansible task to VERIFY the fix was applied correctly.
Return only the verification command/task, nothing else.
"""
