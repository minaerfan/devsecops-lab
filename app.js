// app.js - Intentionally vulnerable web application for DevSecOps learning

// Import the express framework - this is like 'include' in other languages
const express = require('express');
// Create an instance of an express application
const app = express();
// Import path module for file path operations
const path = require('path');
// Import child_process to run system commands (this is dangerous!)
const { exec } = require('child_process');

// ============ MIDDLEWARE ============
// These are functions that process requests before they reach your routes

// Tell express to parse JSON data in requests (like from APIs)
// VULNERABILITY: No validation on input size or content
app.use(express.json());

// Parse URL-encoded data (from HTML forms)
// VULNERABILITY: extended: true allows any type of data, leading to prototype pollution
app.use(express.urlencoded({ extended: true }));

// Serve static files from the 'public' folder (if you create one)
// app.use(express.static('public'));

// ============ ROUTES ============
// These define what happens when users visit different URLs

// Home page route
app.get('/', (req, res) => {
    res.send(`
        <h1>Vulnerable App for DevSecOps Learning</h1>
        <p>This app contains intentional vulnerabilities for testing security tools.</p>
        <h2>Try these vulnerable endpoints:</h2>
        <ul>
            <li><a href="/user?id=1' OR '1'='1">SQL Injection Demo - /user?id=1' OR '1'='1</a></li>
            <li><a href="/search?q=<script>alert('XSS')</script>">XSS Demo - /search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</a></li>
            <li><a href="/ping?ip=127.0.0.1; ls">Command Injection Demo - /ping?ip=127.0.0.1; ls</a></li>
        </ul>
    `);
});

// ============ VULNERABILITY 1: SQL Injection (simulated) ============
// Route that simulates a SQL injection vulnerability
// In real life, this would query a database with unsanitized input
app.get('/user', (req, res) => {
    // Get the 'id' parameter from the URL query string
    // Example: /user?id=123
    const userId = req.query.id;
    
    // VULNERABILITY: Direct string concatenation without sanitization
    // This allows attackers to modify the SQL query structure
    const simulatedQuery = "SELECT * FROM users WHERE id = '" + userId + "'";
    
    res.send(`
        <h2>User Lookup</h2>
        <p><strong>Simulated SQL Query:</strong></p>
        <code>${simulatedQuery}</code>
        <p><strong>Vulnerability:</strong> SQL Injection</p>
        <p>If this were a real database, you could manipulate the query to:</p>
        <ul>
            <li>Bypass authentication (always true condition)</li>
            <li>Retrieve all records (UNION queries)</li>
            <li>Modify data (INSERT/UPDATE/DELETE)</li>
        </ul>
        <p><a href="/">Back</a></p>
    `);
});

// ============ VULNERABILITY 2: Cross-Site Scripting (XSS) ============
// Route that reflects user input without sanitization
app.get('/search', (req, res) => {
    // Get the 'q' parameter from URL (search query)
    const searchTerm = req.query.q;
    
    // VULNERABILITY: Directly inserting user input into HTML
    // This allows attackers to inject JavaScript code
    // If no search term provided, use default message
    const displayTerm = searchTerm || "nothing";
    
    res.send(`
        <h2>Search Results</h2>
        <p>You searched for: ${displayTerm}</p>
        <p><strong>Vulnerability:</strong> Cross-Site Scripting (XSS)</p>
        <p>Try searching for: <code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></p>
        <p>This executes JavaScript in your browser because the input isn't sanitized!</p>
        <p><a href="/">Back</a></p>
    `);
});

// ============ VULNERABILITY 3: Command Injection ============
// Route that executes system commands based on user input
app.get('/ping', (req, res) => {
    // Get the 'ip' parameter from URL
    const ip = req.query.ip;
    
    // VULNERABILITY: No validation/sanitization of input before command execution
    // Attackers can chain commands using ;, &&, ||, etc.
    const command = `ping -c 1 ${ip || '127.0.0.1'}`;
    
    // Execute the command - THIS IS EXTREMELY DANGEROUS IN PRODUCTION!
    exec(command, (error, stdout, stderr) => {
        if (error) {
            res.send(`
                <h2>Ping Results</h2>
                <p>Command: <code>${command}</code></p>
                <p>Error: ${error.message}</p>
                <p><a href="/">Back</a></p>
            `);
            return;
        }
        if (stderr) {
            res.send(`
                <h2>Ping Results</h2>
                <p>Command: <code>${command}</code></p>
                <p>stderr: ${stderr}</p>
                <p><a href="/">Back</a></p>
            `);
            return;
        }
        
        res.send(`
            <h2>Ping Results</h2>
            <p>Command executed: <code>${command}</code></p>
            <pre>${stdout}</pre>
            <p><strong>Vulnerability:</strong> Command Injection</p>
            <p>Try: <code>/ping?ip=127.0.0.1; ls -la</code></p>
            <p><a href="/">Back</a></p>
        `);
    });
});

// ============ VULNERABILITY 4: Path Traversal ============
// Route that serves files based on user input
app.get('/files', (req, res) => {
    // Get filename from query parameter
    const filename = req.query.file;
    
    // VULNERABILITY: No path sanitization allows directory traversal
    // Example: /files?file=../../../etc/passwd
    const filePath = path.join(__dirname, 'public', filename || 'index.html');
    
    res.send(`
        <h2>File Access</h2>
        <p>Attempting to access: ${filePath}</p>
        <p><strong>Vulnerability:</strong> Path Traversal</p>
        <p>Try: <code>/files?file=../../../etc/passwd</code></p>
        <p><a href="/">Back</a></p>
    `);
    // Note: This doesn't actually serve the file, just demonstrates the vulnerability
});

// ============ VULNERABILITY 5: No Rate Limiting ============
// Route with no protection against brute force attacks
app.post('/login', (req, res) => {
    // Get username and password from request body
    const { username, password } = req.body;
    
    // VULNERABILITY: No rate limiting allows unlimited login attempts
    // Also, credentials are sent in plain text (no HTTPS in dev)
    // Hardcoded credentials (bad practice)
    if (username === 'admin' && password === 'admin123') {
        res.json({ success: true, message: 'Login successful!' });
    } else {
        res.status(401).json({ success: false, message: 'Invalid credentials' });
    }
});

// ============ START THE SERVER ============
// Define the port the app will listen on
const PORT = 3000;

// Start the server and log that it's running
app.listen(PORT, () => {
    console.log(`🚀 Vulnerable app is running!`);
    console.log(`📱 Local: http://localhost:${PORT}`);
    console.log(`🌍 Network: http://YOUR-MAC-IP:${PORT} (for Kali VM access)`);
    console.log(`\n⚠️  This app contains INTENTIONAL vulnerabilities for learning!`);
    console.log(`🔧 Never use this code in production!\n`);
});
// TODO: ADD proper logging
