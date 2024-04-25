const Book = require('../Models/Book');

// Create a new book
async function addBook(req, res) {
    try {
        const { title, author, publicationYear } = req.body;

        if (!title || !author || !publicationYear) {
            return res.status(400).json({ message: 'Please provide all fields' });
        }

        // Validate author format
        const authorRegex = /^[a-zA-Z\s]*$/;
        if (!authorRegex.test(author)) {
            return res.status(400).json({ message: 'Invalid author format' });
        }

        // Validate publication year format
        if (!Number.isInteger(publicationYear) || publicationYear <= 0) {
            return res.status(400).json({ message: 'Invalid publication year' });
        }

        // Check if the book already exists
        const existingBook = await Book.findOne({ title, author, publicationYear });
        if (existingBook) {
            return res.status(400).json({ message: 'Book already exists' });
        }

        // Create a new book instance
        const book = new Book({ title, author, publicationYear });

        // Save the new book to the database
        const savedBook = await book.save();

        res.status(201).json(savedBook);
    } catch (error) {
        console.error('Error in addBook:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Get all books or filter by author or publication year
async function getFilterBooks(req, res) {
    try {
        const { author, publicationYear } = req.query;

        if (!author && !publicationYear) {
            return res.status(400).json({ message: 'Provide at least one filter' });
        }


        // Validate author format
        const authorRegex = /^[a-zA-Z\s]*$/;
        if (author && !authorRegex.test(author)) {
            return res.status(400).json({ message: 'Invalid author format' });
        }

        // Validate publication year format
        if (publicationYear && (!Number.isInteger(parseInt(publicationYear)) || parseInt(publicationYear) <= 0)) {
            return res.status(400).json({ message: 'Invalid publication year' });
        }

        // Construct filter object based on provided filters
        const filter = {};
        if (author) filter.author = author;
        if (publicationYear) filter.publicationYear = publicationYear;

        // Find books matching the filter criteria
        const books = await Book.find(filter);
        res.json(books);
    } catch (error) {
        console.error('Error in getFilterBooks:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Update an existing book by ID
async function updateBook(req, res) {
    try {
        const { id } = req.params;
        const { title, author, publicationYear } = req.body;

        if (!title && !author && !publicationYear) {
            return res.status(400).json({ message: 'Provide at least one field to update' });
        }

        // Validate author format
        const authorRegex = /^[a-zA-Z\s]*$/;
        if (!authorRegex.test(author)) {
            return res.status(400).json({ message: 'Invalid author format' });
        }

        // Validate publication year format
        if (!Number.isInteger(publicationYear) || publicationYear <= 0) {
            return res.status(400).json({ message: 'Invalid publication year' });
        }

        // Find and update the book by ID
        const updatedBook = await Book.findByIdAndUpdate(id, { title, author, publicationYear }, { new: true });

        // Check if the book was found and updated successfully
        if (!updatedBook) {
            return res.status(404).json({ message: 'Book not found' });
        }

        res.json(updatedBook);
    } catch (error) {
        console.error('Error in updateBook:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

// Delete a book by ID
async function deleteBook(req, res) {
    try {
        const { id } = req.params;

        // Find and delete the book by ID
        const deletedBook = await Book.findByIdAndDelete(id);

        // Check if the book was found and deleted successfully
        if (!deletedBook) {
            return res.status(404).json({ message: 'Book not found' });
        }

        res.json({ message: 'Book deleted successfully' });
    } catch (error) {
        console.error('Error in deleteBook:', error);
        res.status(500).json({ message: 'Internal server error' });
    }
}

module.exports = { addBook, getFilterBooks, updateBook, deleteBook };
