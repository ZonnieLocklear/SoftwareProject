require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const crypto = require('crypto');  // For generating reset tokens
const nodemailer = require('nodemailer');  // For sending emails

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
    username: { type: String, required: true, unique: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    resetToken: String,
    resetTokenExpiration: Date
});

const User = mongoose.model('User', userSchema);

// Nodemailer transporter configuration
const transporter = nodemailer.createTransport({
    service: 'gmail', // You can use any email service like Gmail, Outlook, etc.
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');  // Serve the main HTML file
});

// Register route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    console.log('Received registration data:', { username, email, password });

    if (!username || !password || !email) {
        return res.status(400).send('All fields are required');
    }

    try {
        // Check if user already exists
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send('User already exists');
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).redirect('/');  // Redirect to login page after registration
    } catch (error) {
        console.error('Error registering user:', error.message);
        res.status(500).send(`Error registering user: ${error.message}`);
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('Received login data:', { username, password });

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('User not found');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        res.sendFile(__dirname + '/homepage.html');  // Redirect to homepage on successful login
    } catch (error) {
        console.error('Error logging in user:', error.message);
        res.status(500).send('Error logging in user');
    }
});

// Forgot password route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;
    console.log('Received forgot password request for email:', email);

    try {
        const user = await User.findOne({ email });
        if (!user) return res.status(400).send('Email not found');

        // Generate a reset token
        const token = crypto.randomBytes(20).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // Token expires in 1 hour
        await user.save();

        // Send email with reset link
        const resetURL = `http://localhost:${PORT}/reset-password/${token}`;
        await transporter.sendMail({
            to: user.email,
            subject: 'Password Reset',
            html: `<p>You requested a password reset. Click <a href="${resetURL}">here</a> to reset your password.</p>`
        });

        res.send('Password reset link sent to your email');
    } catch (error) {
        console.error('Error processing forgot password request:', error.message);
        res.status(500).send('Error processing request');
    }
});

// Reset password route
app.get('/reset-password/:token', async (req, res) => {
    const { token } = req.params;

    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) return res.status(400).send('Invalid or expired token');

        res.sendFile(__dirname + '/reset-password.html');  // Serve the reset password HTML
    } catch (error) {
        console.error('Error displaying reset password page:', error.message);
        res.status(500).send('Error displaying page');
    }
});

app.post('/reset-password/:token', async (req, res) => {
    const { token } = req.params;
    const { password } = req.body;

    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) return res.status(400).send('Invalid or expired token');

        // Hash the new password and update user
        const hashedPassword = await bcrypt.hash(password, 10);
        user.password = hashedPassword;
        user.resetToken = undefined;
        user.resetTokenExpiration = undefined;
        await user.save();

        res.send('Password has been reset successfully');
    } catch (error) {
        console.error('Error resetting password:', error.message);
        res.status(500).send('Error resetting password');
    }
});

// Profile route
app.post('/profile', async (req, res) => {
    const { username, email, newPassword } = req.body;

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('User not found');

        user.email = email;  // Update email if provided
        if (newPassword) {
            // Hash the new password and update it if provided
            const hashedPassword = await bcrypt.hash(newPassword, 10);
            user.password = hashedPassword;
        }
        await user.save();

        res.send('Profile updated successfully');
    } catch (error) {
        console.error('Error updating profile:', error.message);
        res.status(500).send('Error updating profile');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
