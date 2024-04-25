const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const config = require('../env.config');

// Controller function to handle user login
async function loginUser(req, res) {
    const { email, password } = req.body;

    try {
        // Check if both email and password are provided
        if (!email || !password) {
            return res.status(400).json({ message: 'Provide both email and password' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Validate password format
        const passwordRegex = /^[a-zA-Z0-9!@#$%^&*]*$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ message: 'Invalid password format' });
        }

        // Find user by email in the database
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // Compare the provided password with the hashed password stored in the database
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        // If authentication is successful, generate JWT token with user ID payload
        const token = jwt.sign({ userId: user._id }, config.JWT_SECRET, { expiresIn: '10m' });
        res.json({ token });

    } catch (error) {
        console.error('Error in loginUser:', error);
        res.status(500).json({ message: 'Internal server error.' });
    }
}

module.exports = loginUser;
