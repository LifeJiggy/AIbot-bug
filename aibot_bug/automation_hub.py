import os
import json
import asyncio
from ai_manager import AIManager

ai_manager = AIManager()

class AutomationHub:
    @staticmethod
    async def suggest_algorithm(task_description: str):
        prompt = f"Suggest the best-fit algorithm for the following task: {task_description}. Explain why."
        return await ai_manager.analyze(prompt, context="Algorithm Suggestion Engine")

    @staticmethod
    async def resolve_dependency_conflicts(requirements_content: str):
        prompt = f"Analyze these Python dependencies for version conflicts and suggest a stable set of versions:\n\n{requirements_content}"
        return await ai_manager.analyze(prompt, context="Dependency Conflict Resolver")

    @staticmethod
    async def summarize_logs(log_file: str):
        if not os.path.exists(log_file): return "Log file not found."
        with open(log_file, "r") as f: lines = f.readlines()[-50:]
        prompt = f"Summarize these application logs and highlight critical errors:\n\n{''.join(lines)}"
        return await ai_manager.analyze(prompt, context="Log Summarizer")

    @staticmethod
    async def prioritize_issues(findings: dict):
        prompt = f"Prioritize these bug bounty findings by severity (Critical, High, Medium, Low):\n\n{json.dumps(findings)}"
        return await ai_manager.analyze(prompt, context="Issue Prioritizer")

    @staticmethod
    async def predict_scaling():
        prompt = "Based on current bug bounty scan activity, predict when we should scale resources."
        return await ai_manager.analyze(prompt, context="Resource Scaling Predictor")

    @staticmethod
    async def optimize_pipeline():
        prompt = "Suggest optimizations for a bug bounty reconnaissance pipeline using reinforcement learning principles."
        return await ai_manager.analyze(prompt, context="Pipeline Optimizer")

    @staticmethod
    async def code_completion(partial_code: str):
        prompt = f"Complete the following Python code:\n\n{partial_code}"
        return await ai_manager.analyze(prompt, context="AI Code Completion")

    @staticmethod
    async def generate_payloads(vuln_type: str, target_context: str = ""):
        prompt = f"Generate 5 advanced, bypass-oriented payloads for {vuln_type} testing. Target context: {target_context}"
        return await ai_manager.analyze(prompt, context="AI Payload Generator")

    @staticmethod
    async def smart_wordlist(domain: str, category: str = "directories"):
        prompt = f"Generate a list of 20 potential {category} for the domain '{domain}' based on its likely industry and tech stack."
        return await ai_manager.analyze(prompt, context="Smart Wordlist Generator")

    @staticmethod
    async def fingerprint_target(headers: str, body_snippet: str = ""):
        prompt = f"Based on these HTTP headers and body snippet, fingerprint the server tech stack:\n\nHeaders: {headers}\n\nBody: {body_snippet}"
        return await ai_manager.analyze(prompt, context="Target Fingerprinter")

    @staticmethod
    async def exploit_explain(finding: str):
        prompt = f"Explain how a hacker would exploit the following vulnerability: {finding}"
        return await ai_manager.analyze(prompt, context="Exploit Explainability")

    @staticmethod
    async def remediation_advisor(vuln: str):
        prompt = f"Provide a code-level fix for this vulnerability: {vuln}"
        return await ai_manager.analyze(prompt, context="Remediation Advisor")

    @staticmethod
    async def threat_model(target: str):
        prompt = f"Perform a high-level threat model for {target}."
        return await ai_manager.analyze(prompt, context="AI Threat Modeler")

    @staticmethod
    def smart_report_mock(results: dict):
        report_data = f"<h1>Bug Bounty Report</h1><p>Findings: {len(results)}</p>"
        with open("smart_report_mock.html", "w") as f: f.write(report_data)
        return "Smart HTML Report (Mock) generated."

    # --- 5 NEW ADVANCED FEATURES ---
    @staticmethod
    async def vuln_chain_discovery(findings: dict):
        """Analyze minor findings for potential exploit chaining."""
        prompt = f"Analyze these findings and identify if they can be chained into a higher-severity exploit:\n\n{json.dumps(findings)}"
        return await ai_manager.analyze(prompt, context="Vuln Chain Discovery")

    @staticmethod
    async def contextual_bypass_gen(waf_details: str, payload_type: str):
        """Generate bypasses for specific WAF/fitlers."""
        prompt = f"Given the following WAF/filter details: '{waf_details}', generate 3 bypass strategies for {payload_type} payloads."
        return await ai_manager.analyze(prompt, context="Contextual Bypass Generator")

    @staticmethod
    async def honeypot_detection(target_data: str):
        """Identify potential honeypots using AI heuristics."""
        prompt = f"Analyze this target response data and identify signs of honeypots or deception technology:\n\n{target_data}"
        return await ai_manager.analyze(prompt, context="Honeypot Detector")

    @staticmethod
    async def sensitive_leak_analyzer(data: str):
        """Scan for credentials or internal path leaks."""
        prompt = f"Scan the following data for leaked credentials, private keys, or internal infrastructure paths:\n\n{data}"
        return await ai_manager.analyze(prompt, context="Leak Analyzer")

    @staticmethod
    async def report_beautifier(raw_results: dict):
        """Convert raw findings into executive-ready summaries."""
        prompt = f"Convert these raw bug bounty findings into a professional executive summary for a C-level audience:\n\n{json.dumps(raw_results)}"
        return await ai_manager.analyze(prompt, context="Report Beautifier")
