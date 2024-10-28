const express = require("express");
const sql = require("mssql");
const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(bodyParser.json());

// JWT Secret Key
const JWT_SECRET = "your_jwt_secret_key"; // Change this to a more secure key in production

// SQL Server connection configuration
const config = {
  user: "your_db_username",
  password: "your_db_password",
  server: "KRISHNA", // Replace with your SQL server address
  database: "clz_recommendation",
  options: {
    encrypt: false, // Set to true if you're using Azure
    trustServerCertificate: true,
  },
};

// Connect to SQL Server
sql.connect(config)
  .then(() => {
    console.log("Connected to SQL Server!");
  })
  .catch((err) => {
    console.error("Connection Failed: ", err);
  });

// Signup endpoint
app.post("/api/auth/signup", async (req, res) => {
  const { full_name, email, phone, password } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if the email or phone already exists
    const checkQuery = `SELECT * FROM students WHERE email = @Email OR phone = @Phone`;
    const pool = await sql.connect(config);
    const checkResult = await pool
      .request()
      .input("Email", sql.VarChar, email)
      .input("Phone", sql.VarChar, phone)
      .query(checkQuery);

    if (checkResult.recordset.length > 0) {
      return res.status(400).json({ message: "Email or Phone already exists." });
    }

    // Insert new user
    const insertQuery = `
      INSERT INTO students (full_name, email, phone, password_hash)
      VALUES (@FullName, @Email, @Phone, @PasswordHash)
    `;
    await pool
      .request()
      .input("FullName", sql.VarChar, full_name)
      .input("Email", sql.VarChar, email)
      .input("Phone", sql.VarChar, phone)
      .input("PasswordHash", sql.VarChar, hashedPassword)
      .query(insertQuery);

    return res.json({ message: "User registered successfully" });
  } catch (error) {
    console.error("Signup Error: ", error);
    return res.status(500).json({ message: "An error occurred during signup" });
  }
});

// Login endpoint
app.post("/api/auth/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    // Check if the user exists
    const checkQuery = `SELECT * FROM students WHERE email = @Email`;
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input("Email", sql.VarChar, email)
      .query(checkQuery);

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: "Invalid email or password." });
    }

    const user = result.recordset[0];

    // Compare the provided password with the hashed password
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password." });
    }

    // Generate a JWT token
    const token = jwt.sign({ studentId: user.student_id, email: user.email }, JWT_SECRET, {
      expiresIn: "1h",
    });

    return res.json({ token, message: "Login successful" });
  } catch (error) {
    console.error("Login Error: ", error);
    return res.status(500).json({ message: "An error occurred during login" });
  }
});

// Middleware: Verify JWT token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"];
  if (!token) {
    return res.status(403).json({ message: "No token provided." });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(403).json({ message: "Failed to authenticate token." });
    }
    req.studentId = decoded.studentId;
    next();
  });
};

// Protected route example: Get current student profile
app.get("/api/auth/profile", verifyToken, async (req, res) => {
  const { studentId } = req;

  try {
    const query = `SELECT full_name, email, phone FROM students WHERE student_id = @StudentId`;
    const pool = await sql.connect(config);
    const result = await pool
      .request()
      .input("StudentId", sql.Int, studentId)
      .query(query);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: "User not found." });
    }

    return res.json(result.recordset[0]);
  } catch (error) {
    console.error("Profile Fetch Error: ", error);
    return res.status(500).json({ message: "An error occurred while fetching profile" });
  }
});

// Start the server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
