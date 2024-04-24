const registerUser = require("./register");
const loginUser = require("./login");
const { getFilterBooks, addBook, updateBook, deleteBook } = require("./book");

const routes = [
    {
        path: "/register",
        method: "POST",
        name: "User Registration",
        describe: "Register a new user",
        functionName: registerUser
    },
    {
        path: "/login",
        method: "POST",
        name: "User Login",
        describe: "Authenticate user login",
        functionName: loginUser
    },
    {
        path: "/books",
        method: "GET",
        name: "Get All Filtered Books",
        describe: "Get all Filtered books",
        functionName: getFilterBooks
    },
    {
        path: "/books",
        method: "POST",
        name: "Add Book",
        describe: "Add a new book",
        functionName: addBook
    },
    {
        path: "/books/:id",
        method: "PUT",
        name: "Update Book",
        describe: "Update an existing book",
        functionName: updateBook
    },
    {
        path: "/books/:id",
        method: "DELETE",
        name: "Delete Book",
        describe: "Delete a book",
        functionName: deleteBook
    }
];

module.exports = routes;
