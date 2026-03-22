// vuln_demo_app.js
const express = require('express');
const fs = require('fs');
const path = require('path');
const axios = require('axios');

const app = express();
app.use(express.json());

// ------------------------
// Unsafe environment usage
// ------------------------
const SECRET_KEY = process.env.SECRET_KEY; // ⚠️ Hardcoded secret
process.env.API_TOKEN = "API_TOKEN_123"; // ⚠️ Unsafe env usage

// ------------------------
// Vulnerable endpoints
// ------------------------

// 1. Expose secrets via endpoint
app.get('/leak', (req, res) => {
    res.json({
        secretKey: SECRET_KEY,
        apiToken: process.env.API_TOKEN
    });
});

// 2. SQL Injection simulation (dummy DB)
const users = [{ id: 1, username: 'admin', password: 'password' }];
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    // ⚠️ Unsafe string comparison simulating SQL injection
    const user = users.find(u => u.username === username && u.password === password);
    if (user) return res.json({ message: 'Logged in!' });
    res.status(401).json({ message: 'Invalid credentials' });
});

// 3. Unsafe file read (path traversal)
app.get('/read', (req, res) => {
    const file = req.query.file;
    // ⚠️ Unsafe path handling
    const safeBasePath = path.join(__dirname, 'safe_directory'); // Define a safe base directory
    const safePath = path.resolve(safeBasePath, file);
    if (!safePath.startsWith(safeBasePath)) {
        return res.status(400).send('Invalid file path');
    }
    const content = fs.readFileSync(safePath, 'utf8');
    res.send(`<pre>${content}</pre>`);
});

// 4. Command Injection simulation
const { exec } = require('child_process');
app.get('/exec', (req, res) => {
    const cmd = req.query.cmd;
    // ⚠️ Unsafe execution
    const allowedCommands = ['ls', 'pwd']; // Example allowlist
    if (!allowedCommands.includes(cmd)) {
        return res.status(400).send('Command not allowed');
    }
    exec(cmd, (err, stdout, stderr) => {
        if (err) return res.send(stderr);
        res.send(`<pre>${stdout}</pre>`);
    });
});

// 5. XSS endpoint
app.get('/echo', (req, res) => {
    const msg = req.query.msg;
    // ⚠️ Unsafe output
    const safeMsg = msg.replace(/</g, "&lt;").replace(/>/g, "&gt;"); // Basic XSS prevention
    res.send(`<h1>You said: ${safeMsg}</h1>`);
});

// ------------------------
// Insecure intervals / memory leak
// ------------------------
setInterval(() => {
    console.log("Fetching unsafe data...");
    axios.get('http://example.com').catch(() => {});
}, 1000); // ⚠️ No rate limiting

let leakArray = [];
setInterval(() => {
    leakArray.push(new Array(10000).fill("leak")); // ⚠️ Memory leak
}, 500);

// ------------------------
// Hardcoded API key in function
// ------------------------
function sendRequest() {
    const apiKey = process.env.API_KEY; // ⚠️ Hardcoded secret
    axios.get(`https://api.example.com/data?key=${apiKey}`)
        .then(res => console.log(res.data))
        .catch(err => console.error(err));
}
setInterval(sendRequest, 2000);

// ------------------------
// Run server
// ------------------------
app.listen(3000, () => {
    console.log("Vulnerable demo server running on http://localhost:3000");
});