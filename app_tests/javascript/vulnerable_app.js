const express = require('express');
const { exec } = require('child_process');
const crypto = require('crypto');

const app = express();

app.get('/search', (req, res) => {
    const userInput = req.query.q;
    
    // Command injection vulnerability
    exec(`find . -name "${userInput}"`, (error, stdout, stderr) => {
        if (error) {
            console.error(error);
            return;
        }
        res.send(stdout);
    });
});

app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    
    // SQL injection vulnerability
    const query = `SELECT * FROM users WHERE id = ${userId}`;
    console.log(query);
    
    // Hardcoded secret
    const jwtSecret = "super_secret_key_123";
    
    // Weak random
    const token = Math.random().toString(36);
    
    // eval usage - code injection
    const userCode = req.query.code;
    if (userCode) {
        eval(userCode);
    }
    
    res.json({ userId, token });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
