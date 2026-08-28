import os

repos = {
    "golang": {
        "main.go": """package main
import (
    "database/sql"
    "fmt"
    "net/http"
    "os"
)
func main() {
    password := "hardcoded_secret_123" // Gosec/Gitleaks: Hardcoded credential
    db, _ := sql.Open("mysql", "user:"+password+"@/dbname")
    http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
        user := r.URL.Query().Get("user")
        db.Exec("SELECT * FROM users WHERE name = '" + user + "'") // SQLi
    })
    http.ListenAndServe(":8080", nil)
}
"""
    },
    "python": {
        "app.py": """import os
import subprocess
from flask import Flask, request

app = Flask(__name__)
SECRET_KEY = "my_super_secret_key" # Bandit/Trufflehog: Hardcoded secret

@app.route('/ping')
def ping():
    ip = request.args.get('ip')
    subprocess.call("ping -c 1 " + ip, shell=True) # Command Injection
    return "Done"
"""
    },
    "node": {
        "app.js": """var express = require('express');
var app = express();
var exec = require('child_process').exec;

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // Secrets

app.get('/exec', function(req, res) {
    exec(req.query.cmd, function(err, stdout, stderr) { // Command Injection
        res.send(stdout);
    });
});
eval("console.log('test')"); // Eval usage
"""
    },
    "php": {
        "index.php": """<?php
$secret = "my_db_password_123";
$id = $_GET['id'];
$conn = new mysqli("localhost", "user", $secret, "db");
$conn->query("SELECT * FROM users WHERE id = " . $id); // SQLi
echo "Hello " . $_GET['name']; // XSS
?>"""
    },
    "java": {
        "App.java": """import java.sql.*;
public class App {
    public static void main(String[] args) throws Exception {
        String secret = "AWS_SECRET_KEY=123456789";
        String user = args[0];
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/test", "user", "pass");
        conn.createStatement().execute("SELECT * FROM users WHERE username = '" + user + "'"); // SQLi
    }
}
"""
    },
    "ruby": {
        "app.rb": """require 'sinatra'
set :session_secret, 'super_secret_key_123'

get '/run' do
  cmd = params[:cmd]
  `#{cmd}` # Command injection
end
"""
    },
    "rust": {
        "main.rs": """fn main() {
    let secret = "super_secret_token";
    unsafe {
        // Unsafe block
        let i = 10;
        println!("{}", i);
    }
}
"""
    },
    "c": {
        "main.c": """#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    char buffer[10];
    strcpy(buffer, argv[1]); // Buffer overflow
    printf("Secret: my_secret_password\n");
    return 0;
}
"""
    },
    "iac": {
        "main.tf": """provider "aws" {
  region = "us-east-1"
}
resource "aws_s3_bucket" "b" {
  bucket = "my-tf-test-bucket"
  acl    = "public-read" // IaC violation
}
""",
        "Dockerfile": """FROM ubuntu:latest
USER root
RUN apt-get update
# Missing apt-get clean
"""
    },
    "smart_contract": {
        "Contract.sol": """pragma solidity ^0.4.15;
contract Vulnerable {
    mapping(address => uint) public balances;
    function withdraw() public {
        uint bal = balances[msg.sender];
        require(bal > 0);
        msg.sender.call.value(bal)(""); // Reentrancy
        balances[msg.sender] = 0;
    }
}
"""
    }
}

base_dir = os.path.join(os.getcwd(), "scratch", "test_repos")
os.makedirs(base_dir, exist_ok=True)

for repo, files in repos.items():
    repo_path = os.path.join(base_dir, repo)
    os.makedirs(repo_path, exist_ok=True)
    for filename, content in files.items():
        with open(os.path.join(repo_path, filename), "w") as f:
            f.write(content)

print(f"Created {len(repos)} dummy vulnerable repositories in {base_dir}")
