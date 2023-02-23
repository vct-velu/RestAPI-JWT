const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');

const app = express();
const PORT = 3000;

// Set up body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// In-memory user database
const users = [];

// Secret key for JWT
const JWT_SECRET_KEY = 'mysecretkey';

// Register a new user
app.post('/register', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Check if the user already exists
    const existingUser = users.find((user) => user.username === username);
    if (existingUser) {
      return res.status(409).send({ message: 'User already exists' });
    }

    // Hash the password and store the user
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = { username, password: hashedPassword };
    users.push(user);

    // Generate a JWT token and send it in the response
    const token = jwt.sign({ username }, JWT_SECRET_KEY);
    res.status(201).send({ message: 'User registered', token });
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: 'Internal server error' });
  }
});

// Login a user
app.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;

    // Find the user in the database
    const user = users.find((user) => user.username === username);
    if (!user) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    // Check the password
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).send({ message: 'Invalid username or password' });
    }

    // Generate a JWT token and send it in the response
    const token = jwt.sign({ username }, JWT_SECRET_KEY);
    res.status(200).send({ message: 'Login successful', token });
  } catch (error) {
    console.log(error);
    res.status(500).send({ message: 'Internal server error' });
  }
});

// Start the server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
