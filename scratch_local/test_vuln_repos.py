import subprocess
import json
import os

# Mapping of ecosystem to the repo directory name and the tools to test
TEST_CASES = {
    "node": {
        "repo": "nodegoat",
        "tools": ["eslint", "jscpd", "npm-audit", "trivy", "grype"]
    },
    "ruby": {
        "repo": "railsgoat",
        "tools": ["brakeman"]
    },
    "iac": {
        "repo": "terragoat",
        "tools": ["checkov", "terrascan", "kubescore", "hadolint"]
    },
    "python": {
        "repo": "vulnerable_flask_app",
        "tools": ["semgrep", "osv-scanner", "pip-audit", "bandit", "radon"]
    }
}

print("=========================================")
print(" Testing Tools against Real Vuln Repos ")
print("=========================================")

for ecosystem, data in TEST_CASES.items():
    repo_name = data["repo"]
    tools = data["tools"]
    print(f"\n[{ecosystem.upper()}] Repo: {repo_name}")
    
    for tool in tools:
        print(f"  --- Testing {tool} ---")
        
        # We need to make sure the repo exists in the container!
        # The container has /workspace/scratch_local mapped? No, we had to docker cp it last time!
        # Assuming the caller has already copied vuln_repos into the container.
        
        target_path = f"/armur/repos/vuln_repos/{repo_name}"
        cmd = ["docker", "exec", "api_service", "/armur/repos/tester_linux", tool, target_path]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            
            if result.returncode != 0:
                print(f"  ❌ Failed (Code {result.returncode}):")
                print(result.stderr.strip()[:200] + "..." if len(result.stderr) > 200 else result.stderr.strip())
                continue
            
            try:
                output_json = json.loads(result.stdout)
                
                # Different tools might have different json structures
                # For Armur unified format, it's usually a list of findings or a dict with "findings"
                count = 0
                if isinstance(output_json, list):
                    count = len(output_json)
                elif isinstance(output_json, dict):
                    # Iterate through all values in the dictionary
                    for k, v in output_json.items():
                        if isinstance(v, list):
                            count += len(v)
                        
                if count > 0:
                    print(f"  ✅ Success: Found {count} findings!")
                else:
                    print(f"  ⚠️ Warning: 0 findings returned (Output: {str(output_json)[:100]}...)")
                    
            except json.JSONDecodeError:
                print(f"  ❌ JSON Parse Error. Raw output:")
                print(result.stdout.strip()[:200] + "..." if len(result.stdout) > 200 else result.stdout.strip())
                
        except subprocess.TimeoutExpired:
            print(f"  ❌ Timeout expired (120s)")

print("\nDone!")
