import os
import subprocess
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "my_super_secret_key" # Bandit/Trufflehog: Hardcoded secret

@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    subprocess.call("ping -c 1 " + ip, shell=True) # Command Injection
    return "Done"
