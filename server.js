require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve static files
app.use(express.static(__dirname));  // Serves all static files (HTML, CSS, JS) in the root directory

// MongoDB connection using environment variable
const uri = process.env.MONGODB_URI;
mongoose.connect(uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
})
    .then(() => console.log('Connected to MongoDB'))
    .catch((error) => console.error('Error connecting to MongoDB:', error));

// User schema and model
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },  // Unique username
    email: { type: String, required: true, unique: true },     // Unique email
    password: { type: String, required: true },
    resetToken: String,
    resetTokenExpiration: Date,
});

const User = mongoose.model('User', userSchema);

// Nodemailer configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');  // Serve the main HTML file
});

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    console.log('Received registration data:', { username, email, password });  // Log the incoming data

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    try {
        // Check if username or email already exists
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this username or email already exists' });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        console.error('Error registering user:', error.message);  // More detailed error logging
        res.status(500).json({ error: `Error registering user: ${error.message}` });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('Received login data:', { username, password });  // Log the incoming data

    try {
        // Find user by either username or email
        const user = await User.findOne({ $or: [{ username }, { email: username }] });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        res.json({ message: 'User logged in successfully', success: true, redirectUrl: '/Homepage.html' });
    } catch (error) {
        console.error('Error logging in user:', error.message);  // More detailed error logging
        res.status(500).json({ error: 'Error logging in user' });
    }
});

// Forgot Password Endpoint
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log('Received forgot password request for email:', email);  // Log the incoming data

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'Email not found' });
        }

        // Generate a reset token
        const token = crypto.randomBytes(32).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

        // Send reset email
        const resetUrl = `http://localhost:${PORT}/reset-password?token=${token}`;
        await transporter.sendMail({
            to: email,
            from: process.env.EMAIL_USER,
            subject: 'Password Reset',
            html: `<p>You requested a password reset</p><p>Click this <a href="${resetUrl}">link</a> to set a new password.</p>`,
        });

        res.json({ message: 'Password reset email sent successfully' });
    } catch (error) {
        console.error('Error in forgot password:', error.message);
        res.status(500).json({ error: 'Error processing forgot password request' });
    }
});

// Reset Password Endpoint
app.get('/reset-password', (req, res) => {
    res.sendFile(__dirname + '/reset-password.html');  // Serve the reset password page
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

        // Hash the new password and update the user record
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.json({ message: 'Password reset successfully' });
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).json({ error: 'Error resetting password' });
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
