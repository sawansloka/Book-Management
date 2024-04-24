require('dotenv').config()
const config = {
    DB_URI: process.env.DB_URI || "mongodb://localhost:27017/local-test-service?retryWrites=true&w=majority&appName=bookManagement",
    PORT: process.env.PORT || 3002,
    JWT_SECRET: process.env.JWT_SECRET || "007sawan"
}

module.exports = config;
