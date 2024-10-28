// server.js
const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const router = express.Router();
const collegeRoutes = require('./routes/collegeRoutes');
const studentRoutes = require('./routes/studentRoutes');
const reviewRoutes = require('./routes/reviewRoutes');
const path = require('path');
require('dotenv').config();

const app = express();
const { connectToDatabase } = require('./db'); // Import db.js instead of dbConfig.js
// Define the CORS options
const corsOptions = {
  credentials: true,
  origin: ['http://localhost:3000', 'http://localhost:80'] // Whitelist the domains you want to allow
};

// Middleware
app.use(cors(corsOptions));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
const userRoutes = require('./routes/userRoutes');
// Serve static files from uploads folder
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use('/users',userRoutes)
// College, Student, and Review routes
app.use('/api/colleges', collegeRoutes);
app.use('/api/auth', studentRoutes);
app.use('/api/review', reviewRoutes);

// Start the server after database connection is established
const PORT = process.env.PORT || 5000;

const startServer = async () => {
  try {
    // Connect to the database before starting the server
    await connectToDatabase();
    
  } catch (error) {
    console.error("Error starting the server:", error);
  }
};

// const dbConfig = {
//   user: 'sa',          // replace with your SQL Server username
//   password: '123',      // replace with your SQL Server password
//   server: 'localhost\\MSSQLSERVER04',            // replace with your SQL Server server
//   database: 'sqlserverconnection',            // replace with your database name
//   options: {
//       encrypt: false,             // set to true if using Azure
//       trustServerCertificate: true // for local development
//   }
// };

// const poolPromise = new sql.ConnectionPool(dbConfig)
//   .connect()
//   .then(pool => {
//     a=pool.request().query('SELECT * FROM college');
//     console.log(a);
//     console.log('Connected to SQL Server');
//     return pool;
//   })
//   .catch(err => console.log('Database Connection Failed!', err));

// module.exports = {
//   sql, poolPromise
// };
// // // Test database connection
// // sql.connect(dbConfig, err => {
// //   if (err) console.log('Database connection failed:', err);
// //   else console.log('Database connected!');
// // });
app.listen(PORT, () => {
  console.log(`Server is starting on http://localhost:${PORT}`);
})
// // startServer();
// // const sql = require('node-sql');

// // const db = sql.connect({
// //     type: 'mssql',
// //     host: 'localhost\\MSSQLSERVER04',
// //     user: 'sa',
// //     password: '123',
// //     database: 'mssqlconnection'
// // });

