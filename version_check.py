import subprocess
import json
import urllib.request
from packaging import version

tools = {
    'pip': ['semgrep', 'bandit', 'pydocstyle', 'radon', 'pylint', 'checkov', 'vulture', 'trufflehog3'],
    'npm': ['eslint', 'jscpd'],
    'go': [
        'github.com/securego/gosec/v2',
        'github.com/fzipp/gocyclo',
        'golang.org/x/tools/cmd/deadcode',
        'github.com/google/osv-scanner'
    ]
}

print("Checking latest versions from package managers...")

for tool in tools['pip']:
    try:
        url = f"https://pypi.org/pypi/{tool}/json"
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode())
            latest = data['info']['version']
            print(f"PIP - {tool}: latest is {latest}")
    except Exception as e:
        print(f"PIP - {tool}: error checking - {e}")

for tool in tools['npm']:
    try:
        output = subprocess.check_output(['npm', 'view', tool, 'version'], text=True).strip()
        print(f"NPM - {tool}: latest is {output}")
    except Exception as e:
        print(f"NPM - {tool}: error checking - {e}")

for pkg in tools['go']:
    try:
        output = subprocess.check_output(['go', 'list', '-m', '-versions', pkg], text=True, stderr=subprocess.DEVNULL)
        if output:
            versions = output.split()
            latest = versions[-1] if len(versions) > 1 else 'unknown'
            print(f"GO - {pkg}: latest is {latest}")
        else:
             print(f"GO - {pkg}: output empty")
    except Exception as e:
        # Fallback to github releases API if go list fails
        if 'github.com/' in pkg:
            try:
                repo = "/".join(pkg.split('/')[1:3])
                url = f"https://api.github.com/repos/{repo}/releases/latest"
                req = urllib.request.Request(url)
                with urllib.request.urlopen(req) as response:
                    data = json.loads(response.read().decode())
                    print(f"GO - {pkg}: latest is {data['tag_name']}")
            except:
                print(f"GO - {pkg}: error checking github api")
        else:
            print(f"GO - {pkg}: error checking - {e}")

# Check Trivy
try:
    req = urllib.request.Request("https://api.github.com/repos/aquasecurity/trivy/releases/latest")
    with urllib.request.urlopen(req) as response:
        data = json.loads(response.read().decode())
        print(f"TRIVY - latest is {data['tag_name']}")
except Exception as e:
    print(f"TRIVY: error checking github api")
