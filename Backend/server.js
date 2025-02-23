const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const cors = require('cors'); 

const app = express();
app.use(express.json());
app.use(cookieParser()); 


const corsOptions = {
    origin: ' http://localhost:5173', 
    credentials: true, 
};
app.use(cors(corsOptions)); 

const SECRET_KEY = 'wesam12341234'; 
const saltRounds = 10; 
let users = {}; 


app.get('/', (req, res) => {
    res.json(users);
});
// Register Route (Hash password & store user)
app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    if (users[username]) {
        return res.status(400).json({ message: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    users[username] = { username, password: hashedPassword };

    res.json({ message: 'User registered successfully' });
});

// Login Route (Verify password & generate JWT)
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = users[username];

    if (!user) {
        return res.status(400).json({ message: 'User not found' });
    }

    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
        return res.status(400).json({ message: 'Incorrect password' });
    }

    // Create JWT token
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

    // Store JWT in an HTTP-only cookie
    res.cookie('authToken', token, { httpOnly: true, secure: false, maxAge: 3600000 }); // 1 hour

    res.json({ message: 'Login successful', token });
});

// Middleware to verify JWT token (for protected routes)
const authenticateToken = (req, res, next) => {
    const token = req.cookies.authToken; // Get JWT from cookies

    if (!token) {
        return res.status(401).json({ message: 'Access Denied. No token provided.' });
    }

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) {
            return res.status(403).json({ message: 'Invalid or expired token' });
        }

        req.user = user;
        next();
    });
};


app.get('/protected', authenticateToken, (req, res) => {
    res.json({ message: `Welcome ${req.user.username}! You have access to protected data.` });
});


app.post('/logout', (req, res) => {
    res.clearCookie('authToken');
    res.json({ message: 'Logged out successfully' });
});


const PORT = 3001;
app.listen(PORT, () => {
    console.log(`🚀 Server running on http://localhost:${PORT}`);
});
