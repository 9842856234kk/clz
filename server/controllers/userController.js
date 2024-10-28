const { poolPromise } = require('../db');

async function getAllUsers(req, res) {
  try {
    const pool = await poolPromise;
    const result = await pool.request().query('SELECT * FROM Users');
    res.json(result.recordset);
  } catch (error) {
    res.status(500).send(error.message);
  }
}

async function createUser(req, res) {
  try {
    const pool = await poolPromise;
    const { name, email } = req.body;
    await pool.request()
      .input('name', name)
      .input('email', email)
      .query('INSERT INTO Users (name, email) VALUES (@name, @email)');
    res.status(201).send('User created');
  } catch (error) {
    res.status(500).send(error.message);
  }
}

module.exports = { getAllUsers, createUser };
