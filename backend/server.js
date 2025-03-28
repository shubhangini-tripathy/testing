const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const cors = require('cors');
const { check, validationResult } = require('express-validator');
const db = require('./db'); // Import SQLite database

const app = express();
const PORT = 5000;

// JWT Secret key (should be stored securely in an environment variable)
const JWT_SECRET = 'your_jwt_secret_key';

app.use(cors());
app.use(bodyParser.json());

// Middleware to handle input validation errors
const validateLogin = [
  check('username').notEmpty().withMessage('Username is required'),
  check('password').notEmpty().withMessage('Password is required'),
];

// Middleware to authenticate JWT
const authenticateJWT = (req, res, next) => {
  const token = req.header('Authorization')?.split(' ')[1];

  if (!token) {
    return res.status(401).json({ message: 'Access denied. No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Invalid or expired token' });
    }
    req.user = decoded;
    next();
  });
};

// Login route with input validation and error handling
app.post('/login', validateLogin, (req, res) => {
  // Handle input validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Check if the user exists in the database
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, row) => {
    if (err) {
      return res.status(500).json({ message: 'Database error' });
    }

    if (!row) {
      return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Compare the provided password with the hashed password stored in the database
    bcrypt.compare(password, row.password, (err, isMatch) => {
      if (err || !isMatch) {
        return res.status(401).json({ message: 'Invalid username or password' });
      }

      // Generate JWT token
      const token = jwt.sign({ username: row.username }, JWT_SECRET, { expiresIn: '1h' });
      return res.json({ token });
    });
  });
});

// Example protected route that requires JWT authentication
app.get('/dashboard', authenticateJWT, (req, res) => {
  res.json({ message: `Welcome, ${req.user.username}! This is your dashboard.` });
});

// Route to register a new user (for testing purposes)
app.post('/register', [
  check('username').notEmpty().withMessage('Username is required'),
  check('password').notEmpty().withMessage('Password is required'),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  // Hash the password
  bcrypt.hash(password, 10, (err, hashedPassword) => {
    if (err) {
      return res.status(500).json({ message: 'Error hashing password' });
    }

    // Insert the user into the database
    db.run('INSERT INTO users (username, password) VALUES (?, ?)', [username, hashedPassword], function (err) {
      if (err) {
        return res.status(500).json({ message: 'Error inserting user into database' });
      }

      res.status(201).json({ message: 'User registered successfully' });
    });
  });
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
