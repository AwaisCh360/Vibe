var express = require('express');
var app = express();
var exec = require('child_process').exec;

const AWS_KEY = "AKIAIOSFODNN7EXAMPLE"; // Secrets

app.get('/exec', function(req, res) {
    exec(req.query.cmd, function(err, stdout, stderr) { // Command Injection
        res.send(stdout);
    });
});
eval("console.log('test')"); // Eval usage
