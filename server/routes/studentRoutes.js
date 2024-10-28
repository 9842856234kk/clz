const express = require('express');
const { sql, poolPromise } = require('../db'); // Use connection pool
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const router = express.Router();

// Secret key for JWT
const JWT_SECRET = 'your_jwt_secret_key';

// POST: Signup a new student
router.post('/signup', async (req, res) => {
  const { full_name, email, phone, password } = req.body;

  // Check if the email or phone already exists
  const checkQuery = 'SELECT * FROM students WHERE email = @Email OR phone = @Phone';
  try {
    const pool = await poolPromise; // Use connection pool
    const existingStudent = await pool.request()
      .input('Email', sql.VarChar, email)
      .input('Phone', sql.VarChar, phone)
      .query(checkQuery);

    if (existingStudent.recordset.length > 0) {
      return res.status(400).json({ message: 'Email or phone number already registered.' });
    }

    // Hash the password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Insert the new student into the database
    const insertQuery = `
      INSERT INTO students (full_name, email, phone, password_hash)
      VALUES (@FullName, @Email, @Phone, @PasswordHash)
    `;
    await pool.request()
      .input('FullName', sql.VarChar, full_name)
      .input('Email', sql.VarChar, email)
      .input('Phone', sql.VarChar, phone)
      .input('PasswordHash', sql.VarChar, hashedPassword)
      .query(insertQuery);

    res.status(201).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// POST: Login a student
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  const sqlQuery = 'SELECT * FROM students WHERE email = @Email';
  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request().input('Email', sql.VarChar, email).query(sqlQuery);

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    const student = result.recordset[0];

    // Compare the provided password with the hashed password
    const validPassword = await bcrypt.compare(password, student.password_hash);
    if (!validPassword) {
      return res.status(400).json({ message: 'Invalid email or password.' });
    }

    // Generate JWT token
    const token = jwt.sign({ studentId: student.student_id, email: student.email }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({ token, message: 'Login successful' });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Middleware: Verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(403).json({ message: 'No token provided.' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: 'Failed to authenticate token.' });
    }
    req.studentId = decoded.studentId;
    next();
  });
};

// Protected route example
router.get('/profile', verifyToken, async (req, res) => {
  const { studentId } = req;

  const sqlQuery = 'SELECT * FROM students WHERE student_id = @StudentId';
  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request().input('StudentId', sql.Int, studentId).query(sqlQuery);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'User not found.' });
    }

    res.status(200).json(result.recordset[0]);
  } catch (error) {
    console.error('Profile fetch error:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

module.exports = router;
