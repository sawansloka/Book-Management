const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const User = require('../Models/User');
const config = require('../env.config');

// Controller function to handle user registration
async function registerUser(req, res) {
    const { name, email, password, confirmPassword } = req.body;

    try {
        // Check if all required fields are provided
        if (!name || !email || !password || !confirmPassword) {
            return res.status(400).json({ message: 'Provide all fields' });
        }

        // Validate email format
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: 'Invalid email format' });
        }

        // Validate name format
        const nameRegex = /^[a-zA-Z\s]*$/;
        if (!nameRegex.test(name)) {
            return res.status(400).json({ message: 'Invalid name format' });
        }

        // Validate password format
        const passwordRegex = /^[a-zA-Z0-9!@#$%^&*]*$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({ message: 'Invalid password format' });
        }

        if (password !== confirmPassword) {
            return res.status(400).json({ message: 'Passwords do not match' });
        }

        // Check if user already exists in the database
        let user = await User.findOne({ email });
        if (user) {
            return res.status(400).json({ message: 'User already exists' });
        }

        // Generate salt and hash the password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({
            name,
            email,
            password: hashedPassword
        });

        // Save the new user to the database
        await user.save();

        // Generate JWT token with user ID payload
        const payload = {
            user: {
                _id: user._id
            }
        };

        // Sign the JWT token and send it in the response
        jwt.sign(payload, config.JWT_SECRET, { expiresIn: '10m' }, (err, token) => {
            if (err) {
                console.error('Error signing JWT:', err);
                return res.status(500).json({ message: 'Internal server error' });
            }
            res.json({ token });
        });
    } catch (error) {
        console.error('Error in registerUser:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

module.exports = registerUser;
