const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const config = require("./env.config");
const defineRoutes = require("./Routes/Route");
const registerUser = require("./Controller/register");
const loginUser = require("./Controller/login");
const routes = require("./Controller/routes");

const app = express();

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect(config.DB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
})
    .then(() => console.log('MongoDB database connection established successfully'))
    .catch(error => console.error('MongoDB connection error:', error));

// Define routes
const preAuthRoutes = routes.filter(route => [registerUser, loginUser].includes(route.functionName));
const postAuthRoutes = routes.filter(route => ![registerUser, loginUser].includes(route.functionName));

defineRoutes(app, preAuthRoutes, postAuthRoutes);

// Start the server
const port = config.PORT;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});