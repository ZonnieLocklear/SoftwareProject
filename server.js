// Import environment variables using ES module syntax
import dotenv from 'dotenv';
dotenv.config();

import express from 'express';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import bodyParser from 'body-parser';
import nodemailer from 'nodemailer';
import crypto from 'crypto';
import path from 'path';
import { fileURLToPath } from 'url';
import OpenAI from 'openai';
import axios from 'axios';
import { google } from 'googleapis';
import fs from 'fs';
//Added for Session Handling
import session from 'express-session'


// Define __dirname in ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);


const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'secret', // Replace 'secret' with a secure, random value in production
    resave: false,
    saveUninitialized: false, // Setting to false helps avoid creating sessions for unauthenticated users
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Use true if your site runs on HTTPS
        httpOnly: true, // Helps prevent client-side scripts from accessing the cookie
        maxAge: 24 * 60 * 60 * 1000 // Optional: set session expiration time (e.g., 1 day)
    }
}));


// Serve static files
app.use(express.static(__dirname)); // Serves all static files (HTML, CSS, JS) in the root directory

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
    username: { type: String, required: true, unique: true }, // Unique username
    email: { type: String, required: true, unique: true },    // Unique email
    password: { type: String, required: true },
    resetToken: String,
    resetTokenExpiration: Date,
});

const User = mongoose.model('User', userSchema);

// Flashcards schema and model
const flashcardSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true }, // Link to User collection
    term: { type: String, required: true }, // Flashcard question or term
    definition: { type: String, required: true } // Flashcard answer or definition
});

const Flashcard = mongoose.model('Flashcard', flashcardSchema);


// Nodemailer configuration for password reset
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Registration route
app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
        return res.status(400).json({ error: 'Username, email, and password are required' });
    }

    try {
        const existingUser = await User.findOne({ $or: [{ username }, { email }] });
        if (existingUser) {
            return res.status(400).json({ error: 'User with this username or email already exists' });
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, email, password: hashedPassword });
        await newUser.save();

        res.status(201).json({ message: 'User registered successfully' });
    } catch (error) {
        res.status(500).json({ error: `Error registering user: ${error.message}` });
    }
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ $or: [{ username }, { email: username }] });
        if (!user) return res.status(400).json({ error: 'User not found' });

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).json({ error: 'Invalid credentials' });

        // Ensure this line sets the session properly
        req.session.user = { id: user._id, username: user.username };

        res.json({ message: 'User logged in successfully', success: true, redirectUrl: '/Homepage.html' });
    } catch (error) {
        console.error('Error logging in user:', error.message);
        res.status(500).json({ error: 'Error logging in user' });
    }
});

// Middleware to check if the user is authenticated
function isAuthenticated(req, res, next) {
    console.log('Session data:', req.session); // Debugging line
    if (req.session.user) {
        return next();
    } else {
        res.redirect('/index.html');
    }
}
app.post('/flashcards', async (req, res) => {
    const { term, definition } = req.body;
    const userId = req.session.user?.id; // Get the user ID from the session

    if (!term || !definition) {
        return res.status(400).json({ error: 'Term and definition are required.' });
    }

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        const newFlashcard = new Flashcard({ userId, term, definition });
        await newFlashcard.save();
        res.status(201).json({ message: 'Flashcard added successfully!' });
    } catch (error) {
        console.error('Error adding flashcard:', error.message);
        res.status(500).json({ error: 'Failed to add flashcard.' });
    }
});

app.post('/addFlashcard', async (req, res) => {
    const { term, definition } = req.body;
    const userId = req.session.user?.id; // Ensure user is logged in

    if (!term || !definition) {
        return res.status(400).json({ error: 'Term and definition are required.' });
    }

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        const newFlashcard = new Flashcard({ userId, term, definition });
        await newFlashcard.save();
        res.json({ message: 'Flashcard added successfully!' });
    } catch (error) {
        console.error('Error saving flashcard:', error.message);
        res.status(500).json({ error: 'Failed to save flashcard.' });
    }
});
app.get('/getFlashcards', async (req, res) => {
    const userId = req.session.user?.id; // Ensure user is logged in

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        const flashcards = await Flashcard.find({ userId });
        res.json({ flashcards });
    } catch (error) {
        console.error('Error retrieving flashcards:', error.message);
        res.status(500).json({ error: 'Failed to load flashcards.' });
    }
});
app.delete('/deleteFlashcard/:id', async (req, res) => {
    const userId = req.session.user?.id; // Ensure user is logged in
    const { id } = req.params;

    if (!userId) {
        return res.status(401).json({ error: 'Unauthorized. Please log in.' });
    }

    try {
        const deletedFlashcard = await Flashcard.findOneAndDelete({ _id: id, userId });
        if (!deletedFlashcard) {
            return res.status(404).json({ error: 'Flashcard not found.' });
        }
        res.json({ message: 'Flashcard deleted successfully!' });
    } catch (error) {
        console.error('Error deleting flashcard:', error.message);
        res.status(500).json({ error: 'Failed to delete flashcard.' });
    }
});


// Apply the middleware to protected routes
app.get('/Homepage.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'Homepage.html'));
});

app.get('/profile.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'profile.html'));
});

app.get('/flashcards-quiz.html', isAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'flashcards-quiz.html'));
});

// Logout route to destroy session
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return console.error('Error destroying session:', err);
        }
        res.redirect('/index.html');
    });
});
app.get('/test-protected', isAuthenticated, (req, res) => {
    res.send('You are authenticated!');
});



// Forgot Password route
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ error: 'Email not found' });
        }

        const token = crypto.randomBytes(32).toString('hex');
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000; // Token valid for 1 hour
        await user.save();

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

// Reset Password route
app.get('/reset-password', (req, res) => {
    res.sendFile(__dirname + '/reset-password.html'); // Serve the reset password page
});

app.post('/reset-password', async (req, res) => {
    const { token, password } = req.body;
    try {
        const user = await User.findOne({ resetToken: token, resetTokenExpiration: { $gt: Date.now() } });
        if (!user) {
            return res.status(400).json({ error: 'Invalid or expired token' });
        }

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

// OpenAI API setup with conversation memory
const openai = new OpenAI({
    apiKey: process.env.OPENAI_API_KEY, // Use the OpenAI API key from environment variables
});

const conversationMemory = {}; // In-memory conversation storage

// Endpoint to handle AI suggestions using OpenAI (chat-based)
app.post('/getSuggestions', async (req, res) => {
    const userId = req.body.userId || 'defaultUser'; // Replace with real user ID for a multi-user system
    const topic = req.body.topic;

    if (!topic) {
        return res.status(400).json({ error: 'Please provide a topic or question' });
    }

    // Initialize or retrieve user-specific conversation history, limiting to last 50 messages
    if (!conversationMemory[userId]) conversationMemory[userId] = [
        { role: "system", content: "You are InnovativeAI, a helpful assistant." }
    ];
    const userMessages = conversationMemory[userId].slice(-50); // Get last 50 messages

    // Add new user message to the conversation
    userMessages.push({ role: "user", content: topic });

    try {
        // Send message to OpenAI with context
        const response = await openai.chat.completions.create({
            model: "gpt-4",
            messages: userMessages,
            temperature: 0.6,
            max_tokens: 300,
            top_p: 1,
            frequency_penalty: 0,
            presence_penalty: 0
        });

        const aiResponse = response.choices[0].message.content.trim();

        // Save conversation history by adding AI's response
        conversationMemory[userId].push({ role: "user", content: topic });
        conversationMemory[userId].push({ role: "assistant", content: aiResponse });

        res.json({ suggestions: aiResponse });
    } catch (error) {
        console.error('Error with OpenAI API:', error.message);
        res.status(500).json({ error: 'Error processing AI request' });
    }
});


// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
