// db.js
const sql = require('mssql');

const dbConfig = {
  user: 'sa',          // replace with your SQL Server username
  password: '123',      // replace with your SQL Server password
  server: 'localhost\\MSSQLSERVER04',            // replace with your SQL Server server
  database: 'sqlserverconnection',            // replace with your database name
  options: {
      encrypt: false,             // set to true if using Azure
      trustServerCertificate: true // for local development
  }
};

async function connectToDatabase() {
  try {
    const pool = await sql.connect(dbConfig);
    console.log("Connected to SQL Server");
    return pool;
  } catch (err) {
    console.error("Database connection failed:", err);
    throw err;
  }
}

module.exports = { connectToDatabase };
