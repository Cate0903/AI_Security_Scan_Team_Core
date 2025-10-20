// Example vulnerable JavaScript code
// This file contains intentional security vulnerabilities for demonstration

// XSS vulnerability
function displayUserInput(userInput) {
    document.getElementById('output').innerHTML = userInput;  // XSS001 - Cross-Site Scripting
}

function showMessage(msg) {
    document.write("<p>" + msg + "</p>");  // XSS001 - Cross-Site Scripting
}

// Command injection
const exec = require('child_process').exec;
function runCommand(userCmd) {
    exec('ls ' + userCmd, (error, stdout, stderr) => {  // CMD001 - Command Injection
        console.log(stdout);
    });
}

// Hardcoded credentials
const apiKey = "1234567890abcdef";  // CRED001 - Hardcoded Credentials
const password = "SuperSecret123";  // CRED001 - Hardcoded Credentials

// Path traversal
const fs = require('fs');
function readFile(filename) {
    fs.readFile('/data/' + filename, 'utf8', (err, data) => {  // PATH001 - Path Traversal
        console.log(data);
    });
}

// Insecure deserialization
function parseUserData(jsonString) {
    const data = JSON.parse(jsonString);  // DESER001 - Insecure Deserialization
    return data;
}

// Use of eval
function executeCode(code) {
    eval(code);  // EVAL001 - Dangerous Function
}

// Debug mode
const DEBUG = true;  // DEBUG001 - Debug Mode Enabled

console.log("Example vulnerable JavaScript code");
