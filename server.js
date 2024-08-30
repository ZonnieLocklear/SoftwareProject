require('dotenv').config(); // Load environment variables from .env file

const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

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
    password: { type: String, required: true },
});

const User = mongoose.model('User', userSchema);

// Routes
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');  // Serve the main HTML file
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    console.log('Received registration data:', { username, password });  // Log the incoming data

    if (!username || !password) {
        return res.status(400).send('Username and password are required');
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
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();

        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error('Error registering user:', error.message);  // More detailed error logging
        res.status(500).send(`Error registering user: ${error.message}`);
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    console.log('Received login data:', { username, password });  // Log the incoming data

    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('User not found');

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid credentials');

        res.send('User logged in successfully');
    } catch (error) {
        console.error('Error logging in user:', error.message);  // More detailed error logging
        res.status(500).send('Error logging in user');
    }
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server is running on http://localhost:${PORT}`);
});
