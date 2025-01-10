// load env variable
if (process.env.NODE_ENV != 'production'){
    require("dotenv").config();
}

// import dependencies
const express = require("express");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const connectToDb = require("./config/connectToDb");
const User = require('./models/user');

// create an express app
const app = express();

// configure express app
app.use(express.json());

//connect to database
connectToDb();

// JWT secret key
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';

// POST /api/signup
app.post('/api/signup', async (req, res) => {
    const { username, email, password } = req.body;
    
    try {
        // Check if the email already exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ error: 'Email already in use' });
        }
        const hashedPassword = await bcrypt.hash(password, 10);
        
        // Create the user
        const user = await User.create({
            username,
            email,
            password: hashedPassword,
        });
        
        res.status(201).json({ message: 'User registered successfully', user });
    } catch (err) {
        res.status(400).json({ error: 'Error creating user' });
    }
});

// POST /api/signin
app.post('/api/signin', async (req, res) => {
    const { email, password } = req.body;
    
    try {
        // Find the user by email
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Compare passwords
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ error: 'Invalid credentials' });
        }
        
        // Generate JWT
        const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });
        
        res.json({ message: 'Login successful', token });
    } catch (err) {
        res.status(500).json({ error: 'Error logging in' });
    }
});

// GET /api/protected
app.get('/api/protected', async (req, res) => {
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }
    
    try {
        // Verify JWT
        const decoded = jwt.verify(token, JWT_SECRET);
    
        // Find user by ID
        const user = await User.findById(decoded.id);
        if (!user) {
            return res.status(404).json({ error: 'User not found' });
        }
    
        res.json({ message: 'Access granted', user });
    } catch (err) {
        res.status(401).json({ error: 'Invalid token' });
    }
});

//start our server
app.listen(process.env.PORT, () => {
    console.log(`server running on port ${process.env.PORT}`);
});





