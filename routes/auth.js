const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../models/User');
const router = express.Router();
const UserRepository = require('../repositories/UserRepository');
// Register
router.post('/register', async (req, res) => {

    const { username, email, password } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    try {
         const user = await UserRepository.create({
            username,
            email,
            password: hashedPassword
        });
        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        res.status(400).json({ error: 'Email already exists' });
    }
});

// Login
router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await UserRepository.findByEmail({ email });

        if (!user || !(await bcrypt.compare(password, user.password))) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (err) {
        res.status(500).json({ error: 'Something went wrong during login' });
    }
});


// Middleware to protect routes
function authMiddleware(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ error: 'No token' });

    try {
        const decoded = jwt.verify(authHeader.split(' ')[1], process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        res.status(403).json({ error: 'Invalid token' });
    }
}

// Protected dashboard
router.get('/dashboard', authMiddleware, (req, res) => {
    res.json({ message: 'Welcome to the dashboard!', user   Id: req.user.id });
});

// Logout (optional for JWT)
router.post('/logout', (req, res) => {
    res.json({ message: 'Logged out successfully' });
});

module.exports = router;
