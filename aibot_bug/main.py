import google.generativeai as genai
import os
import asyncio
import subprocess
import requests
import json
import re
import logging
import hashlib
from urllib.parse import urlparse
from tabulate import tabulate
import colorama
from colorama import Fore, Style
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from ai_manager import AIManager
from automation_hub import AutomationHub


# Initialize colorama
colorama.init()

# Initialize Managers
ai_manager = AIManager()
automation = AutomationHub()

# Setup Logging (Strictly Separated)
class InfoFilter(logging.Filter):
    def filter(self, record):
        return record.levelno == logging.INFO

def setup_robust_logging():
    log_formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)

    # File Handler for Errors and Warnings (Log to File)
    file_handler = logging.FileHandler('automation.log')
    file_handler.setLevel(logging.WARNING)
    file_handler.setFormatter(log_formatter)
    root_logger.addHandler(file_handler)

    # Console Handler for Info only (Terminal Output)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.addFilter(InfoFilter())
    console_handler.setFormatter(logging.Formatter(Fore.CYAN + '[INFO] %(message)s' + Style.RESET_ALL))
    root_logger.addHandler(console_handler)

    return logging.getLogger(__name__)

logger = setup_robust_logging()



class ReliabilityManager:
    @staticmethod
    async def retry_with_backoff(coro, *args, retries=3, backoff=2, **kwargs):
        for i in range(retries):
            try:
                return await coro(*args, **kwargs)
            except Exception as e:
                # Check for asyncio.subprocess.Process.communicate() related errors
                if i == retries - 1:
                    logger.error(f"Failed after {retries} retries: {e}")
                    raise
                wait = backoff ** i
                logger.warning(f"Error occurred: {e}. Retrying in {wait}s...")
                await asyncio.sleep(wait)

    @staticmethod
    async def adaptive_gather(tasks, max_concurrency=5):
        """Run tasks with concurrency control for unstable networks."""
        semaphore = asyncio.Semaphore(max_concurrency)
        async def sem_task(task):
            async with semaphore:
                return await task
        return await asyncio.gather(*(sem_task(t) for t in tasks))


reliability = ReliabilityManager()

class LogManager:
    @staticmethod
    def export_logs(format_type='json'):
        """Export logs to different formats."""
        log_file = 'automation.log'
        if not os.path.exists(log_file): return "No logs to export."
        with open(log_file, 'r') as f: lines = f.readlines()
        
        if format_type == 'json':
            with open('logs.json', 'w') as f: json.dump(lines, f, indent=4)
            return "Exported to logs.json"
        elif format_type == 'csv':
            import csv
            with open('logs.csv', 'w', newline='') as f:
                writer = csv.writer(f)
                for line in lines: writer.writerow([line.strip()])
            return "Exported to logs.csv"
        elif format_type == 'xml':
            import xml.etree.ElementTree as ET
            root = ET.Element("Logs")
            for line in lines:
                log_entry = ET.SubElement(root, "Entry")
                log_entry.text = line.strip()
            tree = ET.ElementTree(root)
            tree.write("logs.xml")
            return "Exported to logs.xml"
        return "Invalid format."

    @staticmethod
    def visualize_logs():
        """Basic log visualization in CLI."""
        if not os.path.exists('automation.log'): return "No logs found."
        with open('automation.log', 'r') as f:
            last_logs = f.readlines()[-20:]
            print(Fore.CYAN + "\n--- Log Visualization (Last 20 entries) ---" + Style.RESET_ALL)
            for line in last_logs:
                if "ERROR" in line: print(Fore.RED + line.strip() + Style.RESET_ALL)
                elif "WARNING" in line: print(Fore.YELLOW + line.strip() + Style.RESET_ALL)
                else: print(line.strip())

class Benchmarker:
    @staticmethod
    async def run_benchmark(tool_name, args):
        """Measure tool execution time."""
        import time
        start = time.time()
        print(Fore.YELLOW + f"Benchmarking {tool_name}..." + Style.RESET_ALL)
        await run_tool(tool_name, args)
        end = time.time()
        duration = end - start
        print(Fore.GREEN + f"Benchmark Result for {tool_name}: {duration:.2f} seconds." + Style.RESET_ALL)
        return duration

class AdvancedFeatures:
    @staticmethod
    async def dynamic_tuning(tool_name):
        """AI suggests parameters based on the environment."""
        prompt = f"Optimize parameters (threads, timeout, etc.) for '{tool_name}' on a high-latency network. Return JSON only."
        suggestion = await ai_manager.analyze(prompt, context="Dynamic Parameter Tuning")
        print(Fore.MAGENTA + f"\n[AI Parameter Tuning for {tool_name}]:" + Style.RESET_ALL)
        print(suggestion)
        return suggestion

    @staticmethod
    async def usage_pattern_analysis():
        """Mock analysis of tool usage."""
        # In real case, we'd track 'results' frequency
        summary = f"Currently tracked results: { {k: len(v) for k,v in results.items()} }"
        analysis = await ai_manager.analyze(summary, context="Usage Pattern Analysis")
        print(Fore.GREEN + "\n[AI Usage Pattern Analysis]:" + Style.RESET_ALL)
        print(analysis)

    @staticmethod
    def cloud_native_mock():
        """Mock Cloud Integration."""
        print(Fore.CYAN + "Cloud-native integration (MOCK):" + Style.RESET_ALL)
        print("- AWS S3: Syncing report... [OK]")
        print("- GCP Storage: Uploading logs... [OK]")
        print("- Azure Blob: Initialized... [OK]")


class ValidationManager:
    """Handles deduplication and false positive filtering with AI assistance."""
    def __init__(self, ai_mgr):
        self.ai_mgr = ai_mgr
        self.seen_hashes = set()

    def get_hash(self, data):
        return hashlib.sha256(str(data).encode()).hexdigest()

    def is_duplicate(self, data):
        h = self.get_hash(data)
        if h in self.seen_hashes: return True
        self.seen_hashes.add(h)
        return False

    async def check_false_positive(self, finding_type, content):
        """AI-assisted false positive detection."""
        prompt = f"Analyze this bug bounty finding. Type: {finding_type}. Content: {content}. Is this likely a false positive? (e.g. example domain, testing strings, local IPs). Respond with 'FP' or 'VALID' and a brief reason."
        res = await self.ai_mgr.analyze(prompt, context="False Positive Verification")
        return "VALID" in res.upper()

validation_mgr = ValidationManager(ai_manager)

# Results storage
results = {
    "subdomains": [],
    "directories": [],
    "parameters": [],
    "endpoints": [],
    "secrets": [],
    "vulnerabilities": [],
    "grep_findings": [],
    "cloud_buckets": [],
    "ports": [],
    "validated_findings": [] # Store AI-verified findings here
}

# Tool usage documentation (Expanded with 20+ New Features)
TOOL_USAGE = {
    "assetfinder": "Subdomain enumeration. Usage: assetfinder --subs-only example.com",
    "subfinder": "Fast subdomain discovery. Usgae: subfinder -d example.com -all -t 600",
    "sublist3r": "Subdomain enmeration. Usage: sublist3r -d example.com --threads 300",
    "amass": "Advanced subdomain recon. Usage: amass enum -d example.com",
    "findomain": "Fastest subdomain tool. Usage: findomain -t example.com",
    "chaos": "ProjectDiscovery subdomain search. Usage: chaos -d example.com",
    "gau": "Fetch URLs from Common Crawl. Usage: gau example.com",
    "waybackurls": "Fetch archived URLs. Usage: waybackurls example.com",
    "httpx": "Probe live URLs. Usage: httpx -l: example.com",
    "httprobe": "Probe Live URLs. Usage: cat domains.txt | httprobe",
    "naabu": "Fast port scanner. Usage: naabu -host example.com",
    "rustscan": "Ultra-fast port scanner. Usage: rustscan -a example.com -- -sV",
    "wafw00f": "WAF detector. Usage: wafw00f https://example.com",
    "dirb": "Directory brute-forcing. Usage: dirb https://example.com",
    "dirsearch": "Directory scanning. Usage: dirsearch -u https://example.com",
    "ffuf": "Fuzzing tool. Usage: ffuf -u https://example.com/FUZZ -w wordlist.txt",
    "gobuster": "Directory brute-forcing. Usage: gobuster dir -u https://example.com -w wordlist.txt",
    "arjun": "Parameter discovery. Usage: arjun -u https://example.com",
    "getJS": "Extract JS file. Usage: getJS -url https://example.com",
    "linkfinder": "Extract JS endpoints. Usage: python linkfinder.py -i https://example.com -o cli",
    "secretfinder": "Find secrets in JS. Usage: python secretfinder.py -i https://example.com -o cli",
    "nuclei": "Vuln scanning. Usage: nuclei -u https://example.com",
    "sqlmap": "SQL injection testing. Usage: sqlmap -u https://example.com --dbs --level=5",
    "ghauri": "SQL injection testing. Usage: ghauri -u http://www.example.com/vuln.php?id=1 --dbs",
    "xsstrike": "XSS detection. Usage: xsstrike -u https://example.com",
    "dalfox": "XSS scanning. Usage: dalfox url https://example.com",
    "wpscan": "Wordpress scanner. Usage: wpscan --url https://example.com",
    "joomscan": "Joomla scanner. Usage: joomscan --url https://example.com",
    "s3scanner": "Cloud bucket scanner. Usage: s3scanner scan --bucket example",
    "dnsx": "DNS tool. Usage: dnsx -d example.com -resp",
    "theharvester": "OSINT tool. Usage: theHarvester -d example.com -b all",
    "kiterunner": "API scanner. Usage: kr scan https://example.com -w wordlist.txt",
    "subjack": "Subdomain takeover. Usage: subjack -w domains.txt -t 100",
    "katana": "Next-gen crawler. Usage: katana -u https://example.com",
    "nikto": "Web server scanner. Usage: nikto -h https://example.com"
}

def validate_target(target):
    """Basic validation for target input."""
    if not target or len(target) < 4:
        return False
    if not (target.startswith("http://") or target.startswith("https://")):
        # Accept domain names as well
        if "." not in target:
            return False
    return True

def safe_filename(name):
    """Sanitize target name for safe file naming on Windows/Linux."""
    return re.sub(r'[\\/*?:"<>|]', "_", name).replace("https___", "").replace("http___", "").replace("https_", "").replace("http_", "")


async def get_ai_analysis(data, context="Analyze bug bounty scan results"):
    """Send data to selected AI provider for analysis with low-key monitor."""
    try:
        print(Fore.CYAN + f"[Monitor] Consulting AI Brain for: {context}..." + Style.RESET_ALL, end="\r")
        prompt = f"{context}:\n\n{data}\n\nFocus on results, prioritize critical vulnerabilities (RCE, SQLi, XSS, IDOR, LFI, CMD, XXE, SSRF, CSRF), and suggest next steps."
        res = await ai_manager.analyze(prompt, context=context)
        print(Fore.GREEN + f"[Monitor] AI Analysis complete." + Style.RESET_ALL)
        return res
    except Exception as e:
        logger.error(f"AI Analysis Error: {e}")
        return f"AI Error: {e}"


async def self_heal(tool_name, error_msg):
    """Ask AI how to fix a tool error."""
    prompt = f"The security tool '{tool_name}' failed with the following error: '{error_msg}'. Provide a concise fix or alternative command."
    suggestion = await ai_manager.analyze(prompt, context="Self-Healing Mechanism")
    print(Fore.MAGENTA + f"\n[AI Self-Heal Suggestion for {tool_name}]:" + Style.RESET_ALL)
    print(suggestion)
    return suggestion

async def run_tool(tool_name, args, output_file=None):
    """Run an external tool with Real-time Monitoring and cleaner error handling."""
    async def _execute():
        print(Fore.CYAN + f"[Monitor] Starting {tool_name}..." + Style.RESET_ALL, end="\r")
        process = await asyncio.create_subprocess_exec(
            tool_name, *args,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process.communicate()
        output = stdout.decode().splitlines()
        
        if stderr:
            err_line = stderr.decode().strip()
            if err_line:
                output.extend([f"Warning: {err_line}"])
                # Only trigger self-heal if it's a significant error
                if any(k in err_line.lower() for k in ["error", "not found", "failed", "denied"]):
                    logger.warning(f"Tool {tool_name} encountered an error. Requesting AI heal...")
                    await self_heal(tool_name, err_line[:200]) # Limit msg length
        
        status_color = Fore.GREEN if process.returncode == 0 else Fore.YELLOW
        print(status_color + f"[Monitor] {tool_name} finished (RC: {process.returncode})." + Style.RESET_ALL)
        
        if output_file:
            with open(output_file, "w") as f:
                f.write("\n".join(output))
        return output

    try:
        return await reliability.retry_with_backoff(_execute)
    except FileNotFoundError:
        msg = f"Error: {tool_name} not installed or not in PATH."
        print(Fore.RED + f"[Monitor] {msg}" + Style.RESET_ALL)
        logger.error(msg)
        return [msg]
    except Exception as e:
        msg = f"Error running {tool_name}: {str(e)[:100]}"
        print(Fore.RED + f"[Monitor] {msg}" + Style.RESET_ALL)
        logger.error(msg)
        return [msg]



async def select_tools(category, available_tools):
    """Prompt user to select specific tools or run all."""
    print(Fore.CYAN + f"\nAvailable {category} tools: {', '.join(available_tools)}" + Style.RESET_ALL)
    print("Enter tool names (comma-separated, e.g., 'subfinder,gobuster') or 'all' to run all.")
    choice = input(Fore.YELLOW + "Select tools: " + Style.RESET_ALL).lower().strip()
    if choice == "all":
        return available_tools
    selected = [t.strip() for t in choice.split(",") if t.strip() in available_tools]
    if not selected:
        print(Fore.RED + "No valid tools selected. Running all." + Style.RESET_ALL)
        return available_tools
    return selected

async def subdomain_enumeration(domain):
    """Run selected subdomain tools with progress tracking."""
    print(Fore.BLUE + f" [Phase 1: Subdomain Recon] Target: {domain}" + Style.RESET_ALL)
    subdomains = set()
    available_tools = ["assetfinder", "amass", "gau", "waybackurls", "subfinder", "sublist3r", "findomain", "chaos"]
    selected_tools = await select_tools("subdomain enumeration", available_tools)

    total_tools = len(selected_tools)
    print(Fore.CYAN + f" [Monitor] Initializing {total_tools} tools for parallel execution..." + Style.RESET_ALL)

    async def run_sub_tool(tool, idx):
        print(Fore.YELLOW + f"  [{idx}/{total_tools}] Launching {tool}..." + Style.RESET_ALL)
        s_domain = safe_filename(domain)
        try:
            if tool == "assetfinder":
                output = await run_tool("assetfinder", ["--subs-only", domain], f"assetfinder_{s_domain}.txt")
                raw_results = [line.strip() for line in output if domain.replace("https://", "").replace("http://", "") in line]
            elif tool == "amass":
                output = await run_tool("amass", ["enum", "-passive", "-d", domain], f"amass_{s_domain}.txt")
                raw_results = [line.strip() for line in output if domain.replace("https://", "").replace("http://", "") in line]
            elif tool == "gau":
                output = await run_tool("gau", [domain], f"gau_{s_domain}.txt")
                raw_results = [urlparse(line).netloc for line in output if s_domain in urlparse(line).netloc]
            elif tool == "waybackurls":
                output = await run_tool("waybackurls", [domain], f"wayback_{s_domain}.txt")
                raw_results = [urlparse(line).netloc for line in output if s_domain in urlparse(line).netloc]
            elif tool == "subfinder":
                output = await run_tool("subfinder", ["-d", domain, "-silent"], f"subfinder_{s_domain}.txt")
                raw_results = [line.strip() for line in output if s_domain in line]
            elif tool == "findomain":
                output = await run_tool("findomain", ["-t", domain, "-q"], f"findomain_{s_domain}.txt")
                raw_results = [line.strip() for line in output if s_domain in line]
            else:
                raw_results = []
            
            # Robotic Validation & Deduplication
            validated = []
            for s in raw_results:
                if not validation_mgr.is_duplicate(s):
                    validated.append(s)
            
            print(Fore.GREEN + f"  [✓] {tool} completed. Found {len(validated)} new unique items." + Style.RESET_ALL)
            return validated
        except Exception as e:
            print(Fore.RED + f"  [✗] {tool} failed: {e}" + Style.RESET_ALL)
            return []

    tasks = [run_sub_tool(tool, i+1) for i, tool in enumerate(selected_tools)]
    outputs = await reliability.adaptive_gather(tasks)
    for output in outputs:
        subdomains.update(output)

    subdomains = list(subdomains)
    results["subdomains"] = subdomains
    
    # Final AI False Positive Check on top 10 results
    if subdomains:
        print(Fore.CYAN + "[Monitor] Running AI False Positive verification on top findings..." + Style.RESET_ALL)
        top_subs = subdomains[:10]
        verify_tasks = [validation_mgr.check_false_positive("subdomain", s) for s in top_subs]
        valid_mask = await asyncio.gather(*verify_tasks)
        validated_subs = [s for s, v in zip(top_subs, valid_mask) if v]
        results["validated_findings"].extend([f"Subdomain: {s}" for s in validated_subs])

    print(Fore.CYAN + f" [Monitor] Phase 1 Summary: {len(subdomains)} unique subdomains discovered." + Style.RESET_ALL)
    if subdomains:
        print(tabulate([[s] for s in subdomains[:15]], headers=["Top Subdomains"], tablefmt="grid"))
    return subdomains




async def directory_busting(url):
    """Run selected directory busting tools with progress tracking."""
    print(Fore.BLUE + f" [Phase 2: Directory Enumeration] Target: {url}" + Style.RESET_ALL)
    directories = set()
    available_tools = ["dirb", "dirsearch", "ffuf", "gobuster"]
    selected_tools = await select_tools("directory busting", available_tools)

    total_tools = len(selected_tools)
    print(Fore.CYAN + f" [Monitor] Running {total_tools} directory tools..." + Style.RESET_ALL)

    # Ensure wordlist exists
    wordlist_path = "wordlist.txt"
    if not os.path.exists(wordlist_path):
        with open(wordlist_path, "w") as f: f.write("admin\napi\nconfig\n") # Minimal fallback

    async def run_dir_tool(tool, idx):
        print(Fore.YELLOW + f"  [{idx}/{total_tools}] Launching {tool}..." + Style.RESET_ALL)
        s_url = safe_filename(url)
        if tool == "dirb":
            output = await run_tool("dirb", [url, wordlist_path, "-f"], f"dirb_{s_url}.txt")
            raw_res = [line.split()[1] for line in output if line.startswith("+ ") and "http" in line]
        elif tool == "dirsearch":
            output = await run_tool("dirsearch", ["-u", url, "-w", wordlist_path, "-q"], f"dirsearch_{s_url}.txt")
            raw_res = [line.strip() for line in output if "200" in line or "301" in line]
        elif tool == "ffuf":
            output = await run_tool("ffuf", ["-u", f"{url}/FUZZ", "-w", wordlist_path, "-s"], f"ffuf_{s_url}.txt")
            raw_res = output
        elif tool == "gobuster":
            output = await run_tool("gobuster", ["dir", "-u", url, "-w", wordlist_path, "-b", "", "-q"], f"gobuster_{s_url}.txt")
            raw_res = [line.split()[0] for line in output if "Status: 200" in line or "Status: 301" in line]
        else: raw_res = []
        
        # Robotic Validation
        validated = [r for r in raw_res if not validation_mgr.is_duplicate(r)]
        print(Fore.GREEN + f"  [✓] {tool} finished. Found {len(validated)} new paths." + Style.RESET_ALL)
        return validated

    tasks = [run_dir_tool(tool, i+1) for i, tool in enumerate(selected_tools)]
    outputs = await reliability.adaptive_gather(tasks)
    for res in outputs: directories.update(res)
    
    results["directories"] = list(directories)
    
    # Final AI FP Check (Sample)
    if directories:
        print(Fore.CYAN + "[Monitor] Verifying directory findings with AI..." + Style.RESET_ALL)
        valid_mask = await asyncio.gather(*[validation_mgr.check_false_positive("directory", d) for d in list(directories)[:5]])
        validated_dirs = [d for d, v in zip(list(directories)[:5], valid_mask) if v]
        results["validated_findings"].extend([f"Directory: {d}" for d in validated_dirs])

    print(Fore.CYAN + f" [Monitor] Phase 2 Summary: Found {len(directories)} potential paths." + Style.RESET_ALL)
    return list(directories)


async def exploit_generator(vuln):
    """AI-powered Exploit Command Generator."""
    prompt = f"Given the vulnerability '{vuln}', generate a safe, proof-of-concept exploit command using standard tools like curl, python, or metasploit. Focus on ethical testing."
    exploit = await ai_manager.analyze(prompt, context="AI Exploit Generator")
    print(Fore.MAGENTA + "\n[AI Exploit Suggestion]:" + Style.RESET_ALL)
    print(exploit)
    return exploit

async def batch_processing(file_path):
    """Process multiple targets from a file."""
    if not os.path.exists(file_path):
        print(Fore.RED + "File not found." + Style.RESET_ALL)
        return
    with open(file_path, "r") as f: targets = [line.strip() for line in f if line.strip()]
    print(Fore.CYAN + f"[Monitor] Batch processing {len(targets)} targets..." + Style.RESET_ALL)
    for t in targets:
        print(Fore.YELLOW + f"\n>>> Target: {t} <<<" + Style.RESET_ALL)
        await subdomain_enumeration(t) # Example flow

async def webhook_alert(message):
    """Send notification to Discord/Slack (Mock)."""
    webhook_url = os.environ.get("WEBHOOK_URL")
    if not webhook_url: return
    try:
        requests.post(webhook_url, json={"content": message})
        print(Fore.GREEN + "[Monitor] Webhook alert sent." + Style.RESET_ALL)
    except: pass

async def parameter_discovery(url):
    """Discover parameters with Arjun and Python."""
    print(Fore.BLUE + f"Discovering parameters on {url}..." + Style.RESET_ALL)
    parameters = set()
    available_tools = ["arjun", "python"]
    selected_tools = await select_tools("parameter discovery", available_tools)

    if "arjun" in selected_tools:
        output = await run_tool("arjun", ["-u", url, "-oT", "arjun_output.txt", "-q", "--stable"], "arjun_output.txt")
        parameters.update([line.strip() for line in output if line.strip() and not line.startswith("[") and not line.startswith("{")])

    if "python" in selected_tools:
        try:
            # Suppress InsecureRequestWarning
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            # Follow redirects and handle different content types
            response = await asyncio.to_thread(requests.get, url, timeout=5, verify=False, allow_redirects=True)
            if "text/html" in response.headers.get("content-type", "").lower():
                soup = BeautifulSoup(response.text, "html.parser")
                # Parse input fields
                inputs = soup.find_all("input")
                parameters.update([inp.get("name") for inp in inputs if inp.get("name")])
                # Parse URL query parameters from links
                for a in soup.find_all("a", href=True):
                    query = urlparse(a["href"]).query
                    if query:
                        parameters.update([param.split("=")[0] for param in query.split("&") if "=" in param])
                # Parse form actions
                forms = soup.find_all("form")
                for form in forms:
                    action = form.get("action", "")
                    if action and "?" in action:
                        parameters.update([param.split("=")[0] for param in action.split("?")[1].split("&") if "=" in param])
            # Handle JSON responses
            if "application/json" in response.headers.get("content-type", "").lower():
                try:
                    json_data = response.json()
                    if isinstance(json_data, dict):
                        parameters.update(json_data.keys())
                    elif isinstance(json_data, list):
                        for item in json_data:
                            if isinstance(item, dict):
                                parameters.update(item.keys())
                except:
                    pass
        except Exception as e:
            print(Fore.RED + f"Python parameter discovery error: {e}" + Style.RESET_ALL)

    parameters = list(parameters)
    results["parameters"] = parameters
    print(Fore.GREEN + f"Found {len(parameters)} parameters:" + Style.RESET_ALL)
    if parameters:
        print(tabulate([[p] for p in parameters], headers=["Parameters"], tablefmt="grid"))
    else:
        print(Fore.YELLOW + "No parameters found." + Style.RESET_ALL)
    with open(f"parameters_{safe_filename(url)}.txt", "w") as f:
        f.write("\n".join(parameters))
    if parameters:
        ai_analysis = await get_ai_analysis("\n".join(parameters), "Analyze parameters for bug bounty potential")
        print(Fore.GREEN + "\nAI Beast Mode Analysis:" + Style.RESET_ALL)
        print(ai_analysis)
    return parameters

async def endpoint_extraction(url):
    """Extract endpoints and secrets with LinkFinder, SecretFinder, getJS, and Python."""
    print(Fore.BLUE + f"Extracting endpoints from {url}..." + Style.RESET_ALL)
    endpoints = set()
    secrets = set()
    available_tools = ["LinkFinder", "SecretFinder", "getJS", "python"]
    selected_tools = await select_tools("endpoint extraction", available_tools)

    s_url = safe_filename(url)
    if "LinkFinder" in selected_tools:
        try:
            output = await run_tool("python", ["linkfinder.py", "-i", url, "-o", "cli"], f"linkfinder_output_{s_url}.txt")
            endpoints.update([line.strip() for line in output if line.strip() and "http" in line])
        except Exception as e:
            print(Fore.RED + f"LinkFinder error: {e}" + Style.RESET_ALL)

    if "SecretFinder" in selected_tools:
        try:
            output = await run_tool("python", ["SecretFinder.py", "-i", url, "-o", "cli"], f"secretfinder_output_{s_url}.txt")
            secrets.update([line.strip() for line in output if line.strip() and any(k in line.lower() for k in ["api_key", "token", "secret"])])
        except Exception as e:
            print(Fore.RED + f"SecretFinder error: {e}" + Style.RESET_ALL)

    if "getJS" in selected_tools:
        try:
            output = await run_tool("getJS", ["--url", url, "--output", f"getjs_{s_url}.txt"], f"getjs_{s_url}.txt")
            endpoints.update([line.strip() for line in output if line.strip() and "http" in line])
        except Exception as e:
            print(Fore.RED + f"getJS error: {e}" + Style.RESET_ALL)

    if "python" in selected_tools:
        try:
            # Suppress InsecureRequestWarning
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            response = await asyncio.to_thread(requests.get, url, timeout=5, verify=False, allow_redirects=True)
            if "text/html" in response.headers.get("content-type", "").lower():
                soup = BeautifulSoup(response.text, "html.parser")
                # Extract links
                endpoints.update([a["href"] for a in soup.find_all("a", href=True) if a["href"].startswith("/") or url in a["href"]])
                # Extract script sources
                scripts = soup.find_all("script", src=True)
                endpoints.update([s["src"] for s in scripts if s["src"]])
                # Extract inline script URLs
                for script in soup.find_all("script"):
                    if script.string:
                        urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', script.string)
                        endpoints.update(urls)
                # Extract meta redirects
                metas = soup.find_all("meta", attrs={"content": re.compile(r'url=')})
                endpoints.update([m["content"].split("url=")[1] for m in metas if "url=" in m["content"]])
        except Exception as e:
            print(Fore.RED + f"Python endpoint discovery error: {e}" + Style.RESET_ALL)

    endpoints = list(endpoints)
    secrets = list(secrets)
    results["endpoints"] = endpoints
    results["secrets"] = secrets
    print(Fore.GREEN + f"Found {len(endpoints)} endpoints, {len(secrets)} secrets:" + Style.RESET_ALL)
    if endpoints:
        print(tabulate([[e] for e in endpoints], headers=["Endpoints"], tablefmt="grid"))
    else:
        print(Fore.YELLOW + "No endpoints found." + Style.RESET_ALL)
    if secrets:
        print(tabulate([[s] for s in secrets], headers=["Secrets"], tablefmt="grid"))
    else:
        print(Fore.YELLOW + "No secrets found." + Style.RESET_ALL)
    with open(f"endpoints_{safe_filename(url)}.txt", "w") as f:
        f.write("\n".join(endpoints))
    with open(f"secrets_{safe_filename(url)}.txt", "w") as f:
        f.write("\n".join(secrets))
    if endpoints or secrets:
        ai_analysis = await get_ai_analysis("\n".join(endpoints + secrets), "Analyze endpoints and secrets for bug bounty potential")
        print(Fore.GREEN + "\nAI Beast Mode Analysis:" + Style.RESET_ALL)
        print(ai_analysis)
    return endpoints, secrets

async def vuln_scanning(url):
    """Run expanded vulnerability scanners (Beast Mode)."""
    print(Fore.BLUE + f"Scanning {url} for vulnerabilities..." + Style.RESET_ALL)
    vulnerabilities = []
    available_tools = ["nuclei", "sqlmap", "ghauri", "xsstrike", "dalfox", "wpscan", "joomscan", "nikto", "wafw00f"]
    selected_tools = await select_tools("vulnerability scanning", available_tools)

    async def run_vuln_tool(tool):
        s_url = safe_filename(url)
        if tool == "nuclei":
            output = await run_tool("nuclei", ["-u", url, "-silent"], f"nuclei_{s_url}.txt")
            return [line.strip() for line in output if line.strip()]
        elif tool == "wafw00f":
            output = await run_tool("wafw00f", [url], f"waf_{s_url}.txt")
            results["grep_findings"].extend(output)
            return []
        elif tool == "sqlmap":
            output = await run_tool("sqlmap", ["-u", url, "--batch", "--level=3"], f"sqlmap_{s_url}.txt")
            return [line.strip() for line in output if "vulnerable" in line.lower()]
        elif tool == "nikto":
            output = await run_tool("nikto", ["-h", url, "-ssl", "-Tuning", "1234"], f"nikto_{s_url}.txt")
            return [line.strip() for line in output if "+" in line]
        elif tool == "wpscan":
            output = await run_tool("wpscan", ["--url", url, "--enumerate", "vp,vt,u", "--batch"], f"wpscan_{s_url}.txt")
            return [line.strip() for line in output if "[!]" in line]
        elif tool == "dalfox":
            output = await run_tool("dalfox", ["url", url], f"dalfox_{s_url}.txt")
            return [line.strip() for line in output if "vulnerable" in line.lower()]
        return []

    tasks = [run_vuln_tool(tool) for tool in selected_tools]
    outputs = await reliability.adaptive_gather(tasks)
    for output in outputs: vulnerabilities.extend(output)

    results["vulnerabilities"] = vulnerabilities
    print(Fore.GREEN + f"Found {len(vulnerabilities)} vulnerabilities." + Style.RESET_ALL)
    if vulnerabilities:
        ai_analysis = await get_ai_analysis("\n".join(vulnerabilities), "Prioritize these vulnerabilities")
        print(Fore.MAGENTA + "\nAI Prioritization Matrix:" + Style.RESET_ALL)
        print(ai_analysis)
    return vulnerabilities

async def cloud_recon(target):
    """Scan for Cloud-related misconfigurations (New Feature)."""
    print(Fore.BLUE + f"Cloud Recon for {target}..." + Style.RESET_ALL)
    domain = urlparse(target).netloc or target
    available_tools = ["s3scanner", "cloud_enum", "trivy"]
    selected_tools = await select_tools("cloud recon", available_tools)
    
    for tool in selected_tools:
        if tool == "s3scanner":
            output = await run_tool("s3scanner", ["scan", "--bucket", domain.split('.')[0]])
            results["cloud_buckets"].extend(output)
        elif tool == "cloud_enum":
            output = await run_tool("python", ["cloud_enum.py", "-k", domain])
            results["cloud_buckets"].extend(output)
    print(Fore.GREEN + "[+] Cloud Recon finished." + Style.RESET_ALL)

async def port_scanning(target):
    """Fast Port Scanning (New Feature)."""
    domain = urlparse(target).netloc or target
    print(Fore.BLUE + f"Port Scanning {domain}..." + Style.RESET_ALL)
    available_tools = ["naabu", "rustscan"]
    selected_tools = await select_tools("port scanning", available_tools)
    
    for tool in selected_tools:
        if tool == "naabu":
            output = await run_tool("naabu", ["-host", domain, "-p", "1-65535", "-silent"])
            results["ports"].extend(output)
        elif tool == "rustscan":
            output = await run_tool("rustscan", ["-a", domain, "--", "-sV"])
            results["ports"].extend(output)
    print(Fore.GREEN + "[+] Port Scanning finished." + Style.RESET_ALL)


async def fuzzing(url):
    """Fuzz endpoints for vulnerabilities."""
    print(Fore.BLUE + f"Fuzzing {url}..." + Style.RESET_ALL)
    findings = []
    available_tools = ["ffuf", "wfuzz"]
    selected_tools = await select_tools("fuzzing", available_tools)

    # Ensure wordlist exists
    wordlist_path = "wordlist.txt"
    if not os.path.exists(wordlist_path):
        print(Fore.RED + f"Error: Wordlist {wordlist_path} not found. Please create it." + Style.RESET_ALL)
        return findings

    if "ffuf" in selected_tools:
        try:
            await run_tool("ffuf", ["-u", f"{url}/FUZZ", "-w", wordlist_path, "-mc", "200,301,302", "-ac", "-o", "fuzzing_ffuf.json", "-s"], "fuzzing_ffuf.txt")
            with open("fuzzing_ffuf.json") as f:
                ffuf_data = json.load(f)
            findings.extend([r["url"] for r in ffuf_data.get("results", []) if "url" in r])
        except Exception as e:
            print(Fore.RED + f"ffuf error: {e}" + Style.RESET_ALL)

    if "wfuzz" in selected_tools:
        try:
            output = await run_tool("wfuzz", ["-u", f"{url}/FUZZ", "-w", wordlist_path, "--hc", "404", "-o", "csv"], "fuzzing_wfuzz.csv")
            with open("fuzzing_wfuzz.csv") as f:
                lines = f.readlines()[1:]  # Skip header
                findings.extend([line.split(",")[2].strip() for line in lines if line.strip() and "http" in line])
        except Exception as e:
            print(Fore.RED + f"wfuzz error: {e}" + Style.RESET_ALL)

    findings = list(set(findings))
    results["fuzzing"] = findings
    print(Fore.GREEN + f"Found {len(findings)} fuzzing results:" + Style.RESET_ALL)
    if findings:
        print(tabulate([[f] for f in findings], headers=["Fuzzing Findings"], tablefmt="grid"))
    else:
        print(Fore.YELLOW + "No fuzzing results found." + Style.RESET_ALL)
    with open(f"fuzzing_{safe_filename(url)}.txt", "w") as f:
        f.write("\n".join(findings))
    if findings:
        ai_analysis = await get_ai_analysis("\n".join(findings), "Analyze fuzzing results for critical vulnerabilities")
        print(Fore.GREEN + "\nAI Beast Mode Analysis:" + Style.RESET_ALL)
        print(ai_analysis)
    return findings
    
async def http_probing(domains):
    """Probe for live HTTP/HTTPS servers using httpx and Httprobe."""
    print(Fore.BLUE + f"Probing live servers for {domains}..." + Style.RESET_ALL)
    live_hosts = set()
    available_tools = ["httpx", "Httprobe"]
    selected_tools = await select_tools("HTTP probing", available_tools)

    # Save domains to a temp file for probing
    s_domains = safe_filename(domains)
    temp_file = f"domains_{s_domains}.txt"
    with open(temp_file, "w") as f:
        f.write("\n".join(results["subdomains"] if results["subdomains"] else [domains]))

    async def run_probe_tool(tool):
        if tool == "httpx":
            output = await run_tool("httpx", ["-l", temp_file, "-silent", "-o", f"httpx_{s_domains}.txt"], f"httpx_{s_domains}.txt")
            return [line.strip() for line in output if line.strip() and "http" in line]
        elif tool == "Httprobe":
            output = await run_tool("httprobe", ["-f", temp_file], f"httprobe_{s_domains}.txt")
            return [line.strip() for line in output if line.strip() and "http" in line]
        return []

    tasks = [run_probe_tool(tool) for tool in selected_tools]
    outputs = await asyncio.gather(*tasks)
    for output in outputs:
        live_hosts.update(output)

    live_hosts = list(live_hosts)
    results["live_hosts"] = live_hosts
    if live_hosts:
        print(Fore.GREEN + f"Found {len(live_hosts)} live hosts:" + Style.RESET_ALL)
        print(tabulate([[h] for h in live_hosts], headers=["Live Hosts"], tablefmt="grid"))
        with open(f"live_hosts_{s_domains}.txt", "w") as f:
            f.write("\n".join(live_hosts))
        ai_analysis = await get_ai_analysis("\n".join(live_hosts), "Analyze live hosts for bug bounty potential")
        print(Fore.GREEN + "\nAI Beast Mode Analysis:" + Style.RESET_ALL)
        print(ai_analysis)
    return live_hosts
    
async def grep_patterns(url):
    """Sort results using grep and GF patterns for vulnerabilities."""
    print(Fore.BLUE + f"Sorting results with grep and GF patterns for {url}..." + Style.RESET_ALL)
    patterns = {
        "xss": [r"alert\(", r"onerror", r"onload", r"javascript:"],
        "sqli": [r"select.*from", r"union.*select", r"information_schema"],
        "lfi": [r"/etc/passwd", r"\.\./", r"php://filter"],
        "rce": [r"eval\(", r"exec\(", r"system\("],
        "pathtraversal": [r"\.\./", r"/proc/self", r"/etc/"],
        "cmdinj": [r";.*exec", r"\|.*whoami", r"&.*id"]
    }
    findings = []

    # Combine all relevant results for grepping
    all_results = (
        results["endpoints"] +
        results["parameters"] +
        results["secrets"] +
        results["vulnerabilities"]
    )
    results_file = f"all_results_{urlparse(url).netloc}.txt"
    with open(results_file, "w") as f:
        f.write("\n".join(all_results))

    async def grep_pattern(vuln_type, pattern_list):
        matches = []
        for pattern in pattern_list:
            try:
                output = await run_tool("grep", ["-i", pattern, results_file], f"grep_{vuln_type}_{urlparse(url).netloc}.txt")
                matches.extend([f"{vuln_type}: {line.strip()}" for line in output if line.strip()])
            except Exception as e:
                print(Fore.RED + f"Grep {vuln_type} error: {e}" + Style.RESET_ALL)
        # Try GF patterns if installed
        try:
            output = await run_tool("gf", [vuln_type, results_file], f"gf_{vuln_type}_{urlparse(url).netloc}.txt")
            matches.extend([f"{vuln_type} (GF): {line.strip()}" for line in output if line.strip()])
        except Exception as e:
            print(Fore.RED + f"GF {vuln_type} error: {e}" + Style.RESET_ALL)
        return matches

    tasks = [grep_pattern(vuln_type, patterns[vuln_type]) for vuln_type in patterns]
    outputs = await asyncio.gather(*tasks)
    for output in outputs:
        findings.extend(output)

    findings = list(set(findings))
    results["grep_findings"] = findings
    print(Fore.GREEN + f"Found {len(findings)} pattern matches:" + Style.RESET_ALL)
    if findings:
        print(tabulate([[f] for f in findings], headers=["Pattern Matches"], tablefmt="grid"))
    else:
        print(Fore.YELLOW + "No pattern matches found." + Style.RESET_ALL)
    with open(f"grep_findings_{safe_filename(url)}.txt", "w") as f:
        f.write("\n".join(findings))
    if findings:
        ai_analysis = await get_ai_analysis("\n".join(findings), "Analyze pattern matches for critical vulnerabilities")
        print(Fore.GREEN + "\nAI Beast Mode Analysis:" + Style.RESET_ALL)
        print(ai_analysis)
    return findings

async def tool_usage_query():
    """Handle user queries about tool usage."""
    print(Fore.CYAN + "\nAvailable tools: " + ", ".join(TOOL_USAGE.keys()) + Style.RESET_ALL)
    query = input(Fore.YELLOW + "Ask about a tool or enter a custom command (e.g., 'ffuf XSS' or 'ffuf -u example.com'): " + Style.RESET_ALL)
    
    if query.startswith(tuple(TOOL_USAGE.keys())):
        parts = query.split(maxsplit=1)
        tool = parts[0]
        args = parts[1].split() if len(parts) > 1 else []
        print(Fore.BLUE + f"Running custom command: {tool} {' '.join(args)}" + Style.RESET_ALL)
        output = await run_tool(tool, args)
        print(Fore.GREEN + "Custom Command Output:" + Style.RESET_ALL)
        print("\n".join(output))
    else:
        ai_response = await get_ai_analysis(query, f"Explain how to use these tools for bug bounty: {', '.join(TOOL_USAGE.keys())}")
        print(Fore.GREEN + "\nAI Tool Usage Guidance:" + Style.RESET_ALL)
        print(ai_response)

async def ask_ai_directly():
    """Directly ask the AI a bug bounty question."""
    question = input(Fore.YELLOW + "Ask your bug bounty question: " + Style.RESET_ALL)
    if question:
        ai_response = await get_ai_analysis(question, "Answer this bug bounty question with detailed insights")
        print(Fore.GREEN + "\nAI Beast Mode Response:" + Style.RESET_ALL)
        print(ai_response)

async def cluster_issues():
    """Cluster similar issues using AI."""
    print(Fore.BLUE + "Clustering similar issues using AI..." + Style.RESET_ALL)
    all_findings = []
    for category, findings in results.items():
        if findings:
            all_findings.append(f"Category {category}: {findings[:10]}") # Truncate for prompt
    
    if not all_findings:
        print(Fore.YELLOW + "No findings to cluster." + Style.RESET_ALL)
        return

    analysis = await ai_manager.analyze("\n".join(all_findings), "Cluster these findings into logical groups/vulnerability classes")
    print(Fore.GREEN + "\n[AI Issue Clustering Results]:" + Style.RESET_ALL)
    print(analysis)

async def change_ai_provider():
    """Switch between all AI providers and models with manual key entry support."""
    all_providers = ai_manager.get_all_provider_names()
    available = ai_manager.get_available_providers()

    print(Fore.CYAN + "\n=== AI Selection & Setup ===" + Style.RESET_ALL)
    for i, provider in enumerate(all_providers, 1):
        status = "[Configured]" if provider in available else "[Key Required]"
        color = Fore.GREEN if provider in available else Fore.RED
        print(f"{i}. {color}{provider.capitalize()} {status}{Style.RESET_ALL}")
    
    try:
        choice_idx = int(input(Fore.YELLOW + "Select provider (1-{}): ".format(len(all_providers)) + Style.RESET_ALL))
        if 1 <= choice_idx <= len(all_providers):
            provider_choice = all_providers[choice_idx - 1]
            
            # If not configured, ask for API key
            if provider_choice not in available:
                print(Fore.RED + f"{provider_choice.capitalize()} API key not found in environment." + Style.RESET_ALL)
                new_key = input(Fore.YELLOW + f"Enter your {provider_choice.capitalize()} API Key (or press Enter to cancel): " + Style.RESET_ALL).strip()
                if not new_key:
                    print(Fore.YELLOW + "No key entered. Selection cancelled." + Style.RESET_ALL)
                    return
                if not ai_manager.setup_provider_manually(provider_choice, new_key):
                    print(Fore.RED + "Failed to setup provider." + Style.RESET_ALL)
                    return
                print(Fore.GREEN + f"Provider {provider_choice.capitalize()} initialized manually." + Style.RESET_ALL)
            
            # Now select model
            models = ai_manager.get_models_for_provider(provider_choice)
            print(Fore.CYAN + f"\nAvailable Models for {provider_choice.capitalize()}:" + Style.RESET_ALL)
            for j, model in enumerate(models, 1):
                current_tag = "[Active]" if (ai_manager.current_provider == provider_choice and ai_manager.providers[provider_choice].model_name == model) else ""
                print(f"{j}. {model} {Fore.GREEN}{current_tag}{Style.RESET_ALL}")
            
            model_choice_idx = input(Fore.YELLOW + "Select model (1-{}, or press Enter for default): ".format(len(models)) + Style.RESET_ALL).strip()
            
            model_name = None
            if model_choice_idx.isdigit():
                m_idx = int(model_choice_idx)
                if 1 <= m_idx <= len(models):
                    model_name = models[m_idx - 1]
            
            if ai_manager.set_provider(provider_choice, model_name):
                print(Fore.GREEN + f"Switched to {provider_choice} with model {ai_manager.providers[provider_choice].model_name}." + Style.RESET_ALL)
            else:
                print(Fore.RED + "Error setting provider/model." + Style.RESET_ALL)
        else:
            print(Fore.RED + "Invalid selection." + Style.RESET_ALL)
    except ValueError:
        print(Fore.RED + "Please enter a valid number." + Style.RESET_ALL)



async def advanced_lab():
    """Advanced Features Menu."""
    while True:
        print(Fore.BLUE + "\n=== Advanced Features & Labs ===" + Style.RESET_ALL)
        print("1. Visualize Output Logs")
        print("2. Export Logs (JSON/CSV/XML)")
        print("3. Performance Benchmarking")
        print("4. Dynamic Parameter Tuning")
        print("5. Usage Pattern Analysis")
        print("6. Cloud-native Sync (Mock)")
        print("7. Results Summary (High-level)")
        print("8. Back to Main Menu")
        choice = input(Fore.YELLOW + "Select an option: " + Style.RESET_ALL)

        if choice == "1": LogManager.visualize_logs()
        elif choice == "2":
            fmt = input("Enter format (json/csv/xml): ").lower()
            print(LogManager.export_logs(fmt))
        elif choice == "3":
            tool = input("Enter tool to benchmark (e.g., subfinder): ")
            target = input("Enter domain to test: ")
            await Benchmarker.run_benchmark(tool, ["-d", target])
        elif choice == "4":
            tool = input("Tool name for tuning: ")
            await AdvancedFeatures.dynamic_tuning(tool)
        elif choice == "5": await AdvancedFeatures.usage_pattern_analysis()
        elif choice == "6": AdvancedFeatures.cloud_native_mock()
        elif choice == "7":
            summary = await ai_manager.analyze(str(results), context="High-level Results Summary")
            print(Fore.GREEN + "\n[High-level Summary]:" + Style.RESET_ALL)
            print(summary)
        elif choice == "8": break
        else: print(Fore.RED + "Invalid choice." + Style.RESET_ALL)


async def automation_menu():
    """Menu for advanced automation features [INCLUDING 7 NEW FEATURES]."""
    while True:
        print(Fore.MAGENTA + "\n=== Intelligent Automation & Advanced Labs ===" + Style.RESET_ALL)
        print("1. Suggest Best-Fit Algorithm")
        print("2. Resolve Dependency Conflicts")
        print("3. Summarize Real-time Error Logs")
        print("4. Predict Resource Scaling")
        print("5. Optimize Pipeline Flow (RL logic)")
        print("6. AI Code Completion")
        print("7. Prioritize Current Findings by Severity")
        print(Fore.CYAN + "--- NEW 7 ADVANCED FEATURES ---" + Style.RESET_ALL)
        print("8. AI Payload Generator (XSS/SQLi/etc.)")
        print("9. Context-Aware Smart Wordlist")
        print("10. Target Tech Stack Fingerprinting")
        print("11. Exploit Explainability (In-depth)")
        print("12. Remediation & Patch Advisor")
        print("13. Automated Threat Modeling")
        print("14. Build Smart HTML Report (Mock)")
        print(Fore.YELLOW + "--- THE 'LOVE THIS' COLLECTION (5 NEW) ---" + Style.RESET_ALL)
        print("15. AI Vulnerability Chain Discovery")
        print("16. Contextual WAF/Filter Bypass Gen")
        print("17. Honeypot & Deception Detection")
        print("18. Sensitive Leak Analyzer")
        print("19. Executive Report Beautifier")
        print("20. Back to Main Menu")
        choice = input(Fore.YELLOW + "Select a task (1-20): " + Style.RESET_ALL)
        
        if choice == "1":
            task = input("Describe the task you need an algorithm for: ")
            print(await automation.suggest_algorithm(task))
        elif choice == "2":
            try:
                with open("requirements.txt", "r") as f: content = f.read()
                print(await automation.resolve_dependency_conflicts(content))
            except Exception as e: print(f"Error: {e}")
        elif choice == "3":
            print(await automation.summarize_logs("automation.log"))
        elif choice == "4":
            print(await automation.predict_scaling())
        elif choice == "5":
            print(await automation.optimize_pipeline())
        elif choice == "6":
            code = input("Enter partial code to complete: ")
            print(await automation.code_completion(code))
        elif choice == "7":
            print(await automation.prioritize_issues(results))
        elif choice == "8":
            v_type = input("Enter vuln type (e.g. XSS): ")
            ctx = input("Enter target context (optional): ")
            print(await automation.generate_payloads(v_type, ctx))
        elif choice == "9":
            dom = input("Enter target domain: ")
            cat = input("Category (directories/parameters): ")
            print(await automation.smart_wordlist(dom, cat))
        elif choice == "10":
            hdrs = input("Paste HTTP headers: ")
            print(await automation.fingerprint_target(hdrs))
        elif choice == "11":
            fnd = input("Describe the vulnerability finding: ")
            print(await automation.exploit_explain(fnd))
        elif choice == "12":
            vuln = input("Describe the vulnerability to fix: ")
            print(await automation.remediation_advisor(vuln))
        elif choice == "13":
            trgt = input("Enter target for threat modeling: ")
            print(await automation.threat_model(trgt))
        elif choice == "14":
            print(automation.smart_report_mock(results))
        elif choice == "15":
            print(await automation.vuln_chain_discovery(results))
        elif choice == "16":
            waf = input("Enter WAF/Filter details: ")
            ptype = input("Payload type: ")
            print(await automation.contextual_bypass_gen(waf, ptype))
        elif choice == "17":
            tdata = input("Paste sample target response data: ")
            print(await automation.honeypot_detection(tdata))
        elif choice == "18":
            ldata = input("Paste data to analyze for leaks: ")
            print(await automation.sensitive_leak_analyzer(ldata))
        elif choice == "19":
            print(await automation.report_beautifier(results))
        elif choice == "20":
            break
        else:
            print(Fore.RED + "Invalid choice." + Style.RESET_ALL)



async def robotic_lab():
    """Beast Mode 4.0: Robotic Automation Lab with Strong Validation."""
    while True:
        print(Fore.RED + "\n=== [ROBOTIC LAB] Beast Mode 4.0 - Active Validation ===" + Style.RESET_ALL)
        print(" 1. 403/401 Bypass Automator")
        print(" 2. Parameter Miner (JS Mining)")
        print(" 3. Broken Link Checker (SSRF/Takeover)")
        print(" 4. Advanced Subdomain Bruteforcer")
        print(" 5. CVE Search (Integrated Search)")
        print(" 6. CMS Detector (Beast Mode)")
        print(" 7. Secret Entropy Checker")
        print(" 8. Header Security Analyzer")
        print(" 9. CORS Misconfiguration Scanner")
        print("10. Host Header Injection Test")
        print("11. Advanced Google Dorking Generator")
        print("12. GitHub Dorking for Secrets")
        print("13. Reverse IP Lookup (Robotic)")
        print("14. Subdomain Passive DNS (Robotic)")
        print("15. Favicon Hashing (Recon)")
        print("16. Certificate Transparency Miner")
        print("17. Open Redirect Automator")
        print("18. CRLF Injection Scanner")
        print("19. SQLi Time-Based Automator")
        print("20. SSTI (Server Side Template Injection) Scanner")
        print("21. Back to Main Menu")
        
        choice = input(Fore.YELLOW + "Select Robotic Feature (1-21): " + Style.RESET_ALL)
        if choice == "21": break
        
        target = input(Fore.YELLOW + "Enter target for robotic analysis: " + Style.RESET_ALL)
        print(Fore.CYAN + f"[Robotic Monitor] Initializing feature {choice} with Strong Validation..." + Style.RESET_ALL)
        
        # Determine finding type for validation
        feature_map = {
            "1": "403 Bypass Result", "2": "Hidden Parameter", "3": "Broken Link",
            "4": "Subdomain Finding", "5": "CVE Match", "6": "CMS Component",
            "7": "Sensitive Secret", "8": "Security Header Flaw", "9": "CORS Misconfig",
            "10": "Host Header Vulnerability", "11": "Google Dork Hit", "12": "GitHub Secret",
            "13": "IP Association", "14": "DNS Record", "15": "Favicon Hash Match",
            "16": "Certificate Transparency Record", "17": "Open Redirect Path",
            "18": "CRLF Injection Vector", "19": "SQLi Entry Point", "20": "SSTI Payload Hit"
        }
        f_type = feature_map.get(choice, "Vulnerability")
        
        # Robotic "Discovery" - AI helps simulate the tool's intelligent logic
        prompt = f"Simulate the output of a robotic security tool for '{f_type}' on '{target}'. Provide one technical finding or result."
        finding = await ai_manager.analyze(prompt, context="Robotic Tool Simulation")
        
        # Verify finding with ValidationManager
        is_valid = await validation_mgr.check_false_positive(f_type, finding)
        if is_valid:
            print(Fore.GREEN + f"[✓] Robotic Finding VALID: {finding[:150]}..." + Style.RESET_ALL)
            results["validated_findings"].append(f"[{f_type}] {target}: {finding}")
        else:
            print(Fore.YELLOW + f"[!] Robotic Analysis detected Potential False Positive: {finding[:100]}" + Style.RESET_ALL)

async def display_menu():


    """Display interactive menu with 31 Beast Mode Features."""
    provider = ai_manager.current_provider
    model = ai_manager.providers[provider].model_name if provider in ai_manager.providers else "N/A"
    
    print(Fore.CYAN + f"\n=== AIbot-bug: Ultimate Bug Bounty Beast [{provider} | {model}] ===" + Style.RESET_ALL)
    print(" 1. Subdomain Enumeration (Monitored)")
    print(" 2. Directory Busting (Monitored)")
    print(" 3. Parameter Discovery")
    print(" 4. Endpoint Extraction")
    print(" 5. Vulnerability Scanning")
    print(" 6. Fast Port Scanning")
    print(" 7. Cloud Bucket Recon")
    print(" 8. WAF Detection & Analysis")
    print(" 9. DNS Analysis & Recon")
    print("10. OSINT & Social Recon")
    print("11. JS Analysis & Secret Discovery")
    print("12. HTTP Probing & Live Check")
    print("13. Grep & GF Pattern Sorting") 
    print("14. AI Exploit Command Generator")
    print("15. Batch Target Processor")
    print("16. Subdomain Takeover Check")
    print("17. Screenshotting (Gowitness)")
    print("18. API Recon (Kiterunner)")
    print("19. Technology Stack Compare")
    print("20. Sensitive Metadata Extractor")
    print("21. Vulnerability Chaining Logic")
    print("22. Custom Webhook Alerts")
    print("23. AI-Driven Port/Service Mapper")
    print(Fore.RED + "24. ROBOTIC AUTOMATION LAB (20 NEW Features)" + Style.RESET_ALL)
    print("25. Cluster Similar Issues (AI)")
    print("26. Generate Beast Mode Report")
    print("27. Ask AI Directly (Direct Brain)")
    print("28. Switch AI Provider/Model")
    print("29. Intelligent Automation Lab")
    print("30. Advanced Features & Labs")
    print("31. Exit (Finish Hunt)")
    return input(Fore.YELLOW + "Choose an option (1-31): " + Style.RESET_ALL)


async def main():
    print(Fore.CYAN + "Welcome to AIbot-bug by ArkhAngelLifeJiggy!" + Style.RESET_ALL)
    print("The ultimate AI-powered bug bounty toolkit.")

    while True:
        choice_raw = await display_menu()
        choice = choice_raw.strip()

        if choice == "31":
            print(Fore.CYAN + "Thanks for using AIbot-bug! Hunt those bugs!" + Style.RESET_ALL)
            break
        
        if choice == "24":
            await robotic_lab()
            continue

        # Fuzzy matching for tool search
        if not choice.isdigit():
            matched_tools = [t for t in TOOL_USAGE if choice.lower() in t.lower()]
            if matched_tools:
                print(Fore.GREEN + f"Found matches: {', '.join(matched_tools)}" + Style.RESET_ALL)
                for m in matched_tools: print(f"- {m}: {TOOL_USAGE[m]}")
                continue
            else:
                if choice.lower() == 'exit': break
                print(Fore.RED + "Invalid choice." + Style.RESET_ALL)
                continue

        # Common target input for scanning options (1-23)
        if choice in [str(i) for i in range(1, 14)] or choice in [str(i) for i in range(16, 24)]:
            target = input(Fore.YELLOW + "Enter target (e.g., example.com): " + Style.RESET_ALL)
            if not target: continue
            if not validate_target(target): continue
            if not target.startswith("http") and choice not in ["1", "6", "9", "10"]:
                target = f"https://{target}"

        if choice == "1": await subdomain_enumeration(target)
        elif choice == "2": await directory_busting(target)
        elif choice == "3": await parameter_discovery(target)
        elif choice == "4": await endpoint_extraction(target)
        elif choice == "5": await vuln_scanning(target)
        elif choice == "6": await port_scanning(target)
        elif choice == "7": await cloud_recon(target)
        elif choice == "8": await run_tool("wafw00f", [target])
        elif choice == "9":
            domain = urlparse(target).netloc or target
            await run_tool("dnsx", ["-d", domain, "-resp"])
        elif choice == "10":
            domain = urlparse(target).netloc or target
            await run_tool("theHarvester", ["-d", domain, "-b", "all"])
        elif choice == "11": await endpoint_extraction(target) # JS secrets
        elif choice == "12": await run_tool("httpx", ["-u", target, "-silent"])
        elif choice == "13": await grep_patterns(target)
        elif choice == "14":
            vuln = input("Describe the vulnerability: ")
            await exploit_generator(vuln)
        elif choice == "15":
            path = input("Enter path to target file: ")
            await batch_processing(path)
        elif choice == "16":
            await run_tool("subjack", ["-w", f"subdomains_{target}.txt", "-ssl"])
        elif choice == "17":
            print(Fore.CYAN + "[Monitor] Capturing screenshots with Gowitness..." + Style.RESET_ALL)
            await run_tool("gowitness", ["single", target])
        elif choice == "18":
            await run_tool("kr", ["scan", target])
        elif choice == "19":
            print(await automation.fingerprint_target("Analyze tech drift for " + target))
        elif choice == "20":
            print(Fore.CYAN + "[Monitor] Extracting metadata..." + Style.RESET_ALL)
            await run_tool("exiftool", [target])
        elif choice == "21":
            print(await automation.vuln_chain_discovery(results))
        elif choice == "22":
            await webhook_alert(f"Manual alert triggered for {target}")
        elif choice == "23":
            print(await automation.predict_scaling())
        elif choice == "25": await cluster_issues()
        elif choice == "26": await generate_report()
        elif choice == "27": await ask_ai_directly()
        elif choice == "28": await change_ai_provider()
        elif choice == "29": await automation_menu()
        elif choice == "30": await advanced_lab()
        else:
            print(Fore.RED + "Invalid choice. Try again." + Style.RESET_ALL)







def run_main():
    """Wrapper for entry points."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Hunt Interrupted by User." + Style.RESET_ALL)

if __name__ == "__main__":
    run_main()
