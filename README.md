# Book Management System

This project is a Book Management System designed to help users manage their book collections effectively. It provides features for registering users, adding, updating, and deleting books, as well as filtering books by various criteria.

## Installation and Setup
1. Clone the repository to your local machine.
2. Navigate to the project directory.
3. Install dependencies using `npm install`.
4. Create a `.env` file based on the provided `.env.example` file and configure environment variables.
5. Run the application using `npm start`.

## Usage
1. Register a user account using the `/register` endpoint.
2. Log in with your registered credentials using the `/login` endpoint.
3. Use the provided endpoints to manage your book collection:
   - `/books` GET: Retrieve all books or filter by author or publication year.
   - `/books` POST: Add a new book to the collection.
   - `/books/:id` PUT: Update an existing book by ID.
   - `/books/:id` DELETE: Delete a book by ID.

## Project Overview
- **registerUser.js**: Handles user registration and token generation.
- **loginUser.js**: Manages user authentication and token issuance.
- **book.js**: Contains CRUD operations for books (addBook, getFilterBooks, updateBook, deleteBook).
- **Routes/Route.js**: Defines routes for pre-auth and post-auth endpoints.
- **middleware/verifyToken.js**: Middleware function to verify JWT tokens.
- **Models/User.js**: Schema and model for User data.
- **Models/Book.js**: Schema and model for Book data.
- **env.config.js**: Configuration file for environment variables.
- **index.js**: Main entry point for the application.

## Documentation
For detailed documentation, please refer to the [Project Proposal Document]([Tech Doc](https://docs.google.com/document/d/1VN3ZZLOhlTbNQnToNKs6BFdVNkoJnXGp2z9U9StR2ko/edit?usp=sharing)).

## Flow Diagram
([Architecture](https://drive.google.com/file/d/1V1mk3-SFum74OpPqhHxOppJ8ct1qY5Z1/view?usp=sharing))

## Postman Collection
[Postman Collection]([Postman collection](https://www.postman.com/descent-module-cosmologist-51137549/workspace/book-management-system/collection/21309452-d87f1395-b436-44b4-9b87-0a99e517a7ca?action=share&creator=21309452))

## Deployment
This application is hosted on [Book-Management](https://book-management-lwlg.onrender.com).

## Note: Due to inactivity of URL for so long will cause delay of 50-60 seconds for the first time (Render free service issue)
