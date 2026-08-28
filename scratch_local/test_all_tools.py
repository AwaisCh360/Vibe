import subprocess
import json
import os

repo_map = {
    "golang": "golang",
    "python": "python",
    "node": "node",
    "ruby": "ruby",
    "php": "php",
    "c": "c",
    "rust": "rust",
    "iac": "iac",
    "java": "java",
    "smart_contract": "smart_contract",
    "misc": "node" # Use node as generic for some standalone tools
}

tools = {
    "golang": ["gosec", "golint", "govet", "govulncheck", "staticcheck", "gocyclo", "gitleaks"],
    "python": ["bandit", "radon", "pylint", "vulture", "pydocstyle", "pip-audit"],
    "node": ["eslint", "jscpd", "npm-audit"],
    "ruby": ["brakeman"],
    "php": ["phpcs", "psalm"],
    "c": ["cppcheck", "flawfinder"],
    "rust": ["clippy", "cargo-audit", "cargo-geiger"],
    "iac": ["checkov", "terrascan", "tfsec", "kics", "kubelinter", "kubescore", "hadolint"],
    "java": ["spotbugs", "pmd", "dependency-check", "security-scan"],
    "smart_contract": ["slither", "mythril"],
    "misc": ["grype", "trivy", "semgrep", "trufflehog", "cdxgen"]
}

def check_findings(data):
    if not isinstance(data, dict):
        return False, "Output is not a dict"
    
    total_findings = 0
    categories = ["security_issues", "antipatterns_bugs", "complex_functions", "docstring_absent", "sca", "sbom", "compliance"]
    
    for cat in categories:
        if cat in data and isinstance(data[cat], list):
            total_findings += len(data[cat])
            
    if total_findings > 0:
        return True, f"Found {total_findings} findings!"
    
    if data.get("status") == "success":
        return True, "Completed successfully (No generic finding array)"
        
    return False, "0 findings returned"

all_results = {}
total_tested = 0

for ecosystem, tool_list in tools.items():
    repo_name = repo_map.get(ecosystem, ecosystem)
    repo_path = os.path.abspath(f"/workspace/scratch_local/test_repos/{repo_name}")
    
    print(f"\n========================================")
    print(f"Ecosystem: {ecosystem.upper()}")
    print(f"========================================")
    
    for tool in tool_list:
        total_tested += 1
        print(f"\n--- Testing {tool} ---")
        try:
            cmd = ["docker", "exec", "api_service", "/workspace/tester_linux", tool, repo_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            output = result.stdout
            
            if result.returncode != 0:
                print(f"❌ Failed to run: Return code {result.returncode}")
                print(f"Error: {result.stderr.strip() if result.stderr else output.strip()}")
                continue
                
            json_start = output.find('{')
            if json_start != -1:
                json_str = output[json_start:]
                try:
                    data = json.loads(json_str)
                    all_results[tool] = data
                    has_findings, msg = check_findings(data)
                    if has_findings:
                        print(f"✅ Success: {msg}")
                    else:
                        print(f"⚠️ Warning: {msg}")
                except json.JSONDecodeError as e:
                    print(f"❌ Failed to parse JSON: {e}")
            else:
                print(f"❌ Invalid output: No JSON found")
        except subprocess.TimeoutExpired:
            print(f"❌ Timeout expired")
        except Exception as e:
            print(f"❌ Exception: {e}")

print(f"\nDone! Tested {total_tested} tools.")
with open("/Users/bit/.gemini/antigravity-ide/brain/56d5a496-6700-47dd-8c7b-369a81a2fa5c/final_all_findings.json", "w") as f:
    json.dump(all_results, f, indent=2)
print("Saved to final_all_findings.json")
