"""
agents/analyst_agent.py
CrewAI Analyst Agent — interprets STIG findings, explains them in plain
English, and assesses risk impact for the user.
"""

from crewai import Agent
from langchain_community.llms import Ollama
from tools.scanner import STIGFinding


def build_analyst_agent(ollama_model: str, ollama_url: str) -> Agent:
    """Build and return the Analyst Agent."""

    llm = Ollama(
        model=ollama_model,
        base_url=ollama_url,
        temperature=0.3,
    )

    return Agent(
        role="STIG Security Analyst",
        goal=(
            "Analyze STIG findings and translate them into clear, actionable intelligence. "
            "Explain what each failed control means in practical security terms, "
            "what an attacker could do if it remains unpatched, and the business risk it poses."
        ),
        backstory=(
            "You are a cybersecurity analyst who bridges the gap between raw compliance data "
            "and real-world security posture. You excel at explaining complex STIG requirements "
            "to system administrators and helping teams prioritize which vulnerabilities pose "
            "the greatest actual risk. Your explanations are clear, concise, and actionable."
        ),
        llm=llm,
        verbose=True,
        allow_delegation=False,
    )


def build_analysis_prompt(finding: STIGFinding) -> str:
    """Construct the prompt for the analyst to evaluate a single finding."""
    return f"""
You are analyzing the following failed DISA STIG control on a RHEL 9 system.

Rule ID    : {finding.rule_id}
Severity   : {finding.severity}
Title      : {finding.title}
Description: {finding.description}
Check Text : {finding.check_text}

Please provide:
1. PLAIN ENGLISH EXPLANATION (2-3 sentences): What does this control mean and why does it exist?
2. ATTACK SCENARIO (1-2 sentences): How could an attacker exploit this if left unfixed?
3. BUSINESS RISK: Rate as Critical / High / Medium / Low and explain why in one sentence.
4. SIDE EFFECTS: Are there any known side effects or caveats to fixing this on a production system?

Be concise and practical. Avoid jargon where possible.
"""


def build_batch_analysis_prompt(findings: list[STIGFinding]) -> str:
    """Build a prompt to triage and prioritize a batch of findings."""
    finding_list = "\n".join(
        f"- [{f.severity}] {f.rule_id}: {f.title}" for f in findings
    )
    return f"""
You are reviewing the following DISA STIG failures on a RHEL 9 system.

FAILED CONTROLS:
{finding_list}

Please:
1. Identify the TOP 5 most critical findings to address first and briefly explain why.
2. Flag any findings that commonly break system functionality if misapplied.
3. Suggest the best logical ORDER to apply remediations (dependencies, reboots required, etc.)

Be direct and practical.
"""
