const jwt = require('jsonwebtoken');
const config = require('../env.config');

// Middleware function to verify JWT token
function verifyToken(req, res, next) {
    const tokenHeader = req.headers['authorization'];

    if (!tokenHeader)
        return res.status(401).json({ auth: false, message: 'Provide token' });

    // Split the token string to extract the actual token value
    const token = tokenHeader.split(' ')[1];

    jwt.verify(token, config.JWT_SECRET, function (err, decoded) {
        // Handle error if token verification fails
        if (err) {
            if (err.name === 'TokenExpiredError') {
                return res.status(403).json({ auth: false, message: 'Token expired' });
            } else {
                return res.status(403).json({ auth: false, message: 'ACCESS DENIED' });
            }
        }

        // If token verification is successful, set userId in request object and call next middleware
        req.userId = decoded.id;
        next();
    });
}

module.exports = verifyToken;