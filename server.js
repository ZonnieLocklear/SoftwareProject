// Load environment variables from .env file
require('dotenv').config(); 

// Web framework for Node.js
const express = require('express');
// MongoDB object modeling tool
const mongoose = require('mongoose');
// Library for hashing passwords
const bcrypt = require('bcryptjs');
// Middleware for parsing request bodies
const bodyParser = require('body-parser');

// Create an Express application
const app = express();
// Set the port from environment variable or default to 3000
const PORT = process.env.PORT || 3000;

// Middleware
// Parse URL-encoded bodies
app.use(bodyParser.urlencoded({ extended: true }));
// Parse JSON bodies
app.use(bodyParser.json());


    
    
// Serve static files
app.use(express.static(__dirname));  // Serves all static files (HTML, CSS, JS) in the root directory

// MongoDB connection using environment variable
const uri = process.env.MONGODB_URI; // Get MongoDB URI from .env file
mongoose.connect(uri, {
    useNewUrlParser: true, // Use new URL parser (now deprecated)
    useUnifiedTopology: true, // Use new topology engine (now deprecated)
})
    .then(() => console.log('Connected to MongoDB')) // Successful connection
    .catch((error) => console.error('Error connecting to MongoDB:', error)); // Log errors if connection fails

// Define User schema and model for MongoDB
    const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true }, // Username field, required and unique
    password: { type: String, required: true }, // Password field, required
});
// Create User model from schema
const User = mongoose.model('User', userSchema);

// Routes
// Serve the main HTML file (login page)
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});
// Handle user registration
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    console.log('Received registration data:', { username, password });  
  // Validate if username and password are provided
    if (!username || !password) {
        return res.status(400).send('Username and password are required');
    }

    try {
        // Check if user already exists inside the database
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(400).send('User already exists'); // Send error if user exists
        }

        // Hash the user's password for security
        const hashedPassword = await bcrypt.hash(password, 10);

        // Create a new user and save to the database        
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        // Redirect to login page after successful registration
        res.redirect('/index.html'); 
    } catch (error) {
        console.error('Error registering user:', error.message);  // Log error details
        res.status(500).send(`Error registering user: ${error.message}`); // Send error response
    }
});
// Handle user login
app.post('/login', async (req, res) => {
    const { username, password } = req.body; // Extract username and password from request body
    console.log('Received login data:', { username, password });  // Log the incoming data

    try {
        // Find the user in the database
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('User not found'); // Send error if user does not exist
        // Compare the provided password with the stored hashed password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials'); // Send error if passwords do not match

        // Redirect to the homepage upon successful login
        res.redirect('/Homepage.html');
    } catch (error) {
        console.error('Error logging in user:', error.message);  // detailed error logging
        res.status(500).send('Error logging in user'); // Send error response
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`); // server start message
});
