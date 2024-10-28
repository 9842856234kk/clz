const express = require('express');
const {  poolPromise } = require('../db'); // Use connection pool
const multer = require('multer');
const router = express.Router();

// Multer setup for file uploads
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, './uploads'); // Uploads folder
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Unique filename
  },
});

const upload = multer({ storage });

// Create a new college
router.post('/add', upload.single('photo'), async (req, res) => {
  const { name, address, city, courses } = req.body;
  const photo = req.file ? req.file.filename : null;

  const sqlQuery = `
    INSERT INTO college (name, address, city, courses, photos)
    VALUES (@Name, @Address, @City, @Courses, @Photos)
  `;

  try {
    const pool = await poolPromise; // Use connection pool
    await pool.request()
      .input('Name', sql.VarChar, name)
      .input('Address', sql.VarChar, address)
      .input('City', sql.VarChar, city)
      .input('Courses', sql.VarChar, courses)
      .input('Photos', sql.VarChar, photo)
      .query(sqlQuery);
    
    res.status(201).json({ message: 'College added successfully' }); // Use JSON response
  } catch (err) {
    console.error('Failed to add college:', err);
    res.status(500).json({ message: 'Failed to add college' }); // Use JSON response
  }
});



// Get all colleges
router.get('/all', async (req, res) => {
  const sqlQuery = `
    SELECT c.id, c.name, c.address, c.city, c.courses, c.photos,
           AVG(r.rating) AS avg_rating, COUNT(r.rating) AS review_count
    FROM college c
    LEFT JOIN reviews r ON c.id = r.college_id
    GROUP BY c.id, c.name, c.address, c.city, c.courses, c.photos
    ORDER BY avg_rating DESC
    OFFSET 0 ROWS FETCH NEXT 1000 ROWS ONLY
  `;

  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request().query(sqlQuery);
    res.json(result.recordset); // Return the college data
  } catch (err) {
    console.error('Failed to fetch colleges:', err);
    res.status(500).json({ message: 'Failed to fetch colleges' }); // Use JSON response
  }
});


// Get all colleges
router.get('/', async (req, res) => {
  const sqlQuery = `
    SELECT *
    FROM college;`;

    try {
      const pool = await poolPromise;
      const result = await pool.request().query(sqlQuery);
      res.json(result.recordset);
    } catch (error) {
      res.status(500).send(error.message);
    }
});


// Get single college by ID
router.get('/single/:id', async (req, res) => {
  const { id } = req.params;

  const sqlQuery = 'SELECT * FROM college WHERE id = @Id';

  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request().input('Id', sql.Int, id).query(sqlQuery);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'College not found' }); // Use JSON response
    }

    res.json({ college: result.recordset[0] }); // Return college data
  } catch (err) {
    console.error('Failed to fetch college:', err);
    res.status(500).json({ message: 'Failed to fetch college' }); // Use JSON response
  }
});

// Update college
router.put('/update/:id', upload.single('photo'), async (req, res) => {
  const { name, address, city, courses } = req.body;
  const { id } = req.params;
  const photo = req.file ? req.file.filename : null;

  let sqlQuery = `
    UPDATE college SET name = @Name, address = @Address, city = @City, courses = @Courses
  `;
  if (photo) {
    sqlQuery += ', photos = @Photos';
  }
  sqlQuery += ' WHERE id = @Id';

  try {
    const pool = await poolPromise; // Use connection pool
    const request = pool.request()
      .input('Name', sql.VarChar, name)
      .input('Address', sql.VarChar, address)
      .input('City', sql.VarChar, city)
      .input('Courses', sql.VarChar, courses)
      .input('Id', sql.Int, id);
    
    if (photo) {
      request.input('Photos', sql.VarChar, photo);
    }

    await request.query(sqlQuery);
    res.status(200).json({ message: 'College updated successfully' }); // Use JSON response
  } catch (err) {
    console.error('Failed to update college:', err);
    res.status(500).json({ message: 'Failed to update college' }); // Use JSON response
  }
});

// Delete college
router.delete('/delete/:id', async (req, res) => {
  const { id } = req.params;

  const sqlQuery = 'DELETE FROM college WHERE id = @Id';

  try {
    const pool = await poolPromise; // Use connection pool
    await pool.request().input('Id', sql.Int, id).query(sqlQuery);
    res.status(200).json({ message: 'College deleted successfully' }); // Use JSON response
  } catch (err) {
    console.error('Failed to delete college:', err);
    res.status(500).json({ message: 'Failed to delete college' }); // Use JSON response
  }
});

module.exports = router;
