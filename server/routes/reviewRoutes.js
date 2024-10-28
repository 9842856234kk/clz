const express = require('express');
const { sql, poolPromise } = require('../db'); // Use connection pool
const router = express.Router();

// POST: Create a new review
router.post('/rate/:collegeId', async (req, res) => {
  const { studentId, rating, comment } = req.body;
  const { collegeId } = req.params;

  const checkQuery = 'SELECT * FROM reviews WHERE student_id = @StudentId AND college_id = @CollegeId';

  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request()
      .input('StudentId', sql.Int, studentId)
      .input('CollegeId', sql.Int, collegeId)
      .query(checkQuery);

    // Check if the student has already submitted a review
    if (result.recordset.length > 0) {
      return res.status(400).json({ message: 'You have already submitted a review for this college.' });
    }

    const insertQuery = `
      INSERT INTO reviews (student_id, college_id, rating, comments)
      VALUES (@StudentId, @CollegeId, @Rating, @Comment)
    `;
    await pool.request()
      .input('StudentId', sql.Int, studentId)
      .input('CollegeId', sql.Int, collegeId)
      .input('Rating', sql.Int, rating)
      .input('Comment', sql.Text, comment)
      .query(insertQuery);

    res.status(201).json({ message: 'Review submitted successfully!' });
  } catch (err) {
    console.error('Failed to submit review:', err);
    res.status(500).json({ message: 'Failed to submit review' });
  }
});

// GET: Get reviews for a specific college
router.get('/:collegeId', async (req, res) => {
  const { collegeId } = req.params;

  const sqlQuery = `
    SELECT r.*, s.full_name 
    FROM reviews r
    JOIN students s ON r.student_id = s.student_id
    WHERE r.college_id = @CollegeId
  `;

  try {
    const pool = await poolPromise; // Use connection pool
    const result = await pool.request().input('CollegeId', sql.Int, collegeId).query(sqlQuery);

    if (result.recordset.length === 0) {
      return res.status(404).json({ message: 'No reviews found for this college.' });
    }

    res.status(200).json(result.recordset);
  } catch (err) {
    console.error('Failed to fetch reviews:', err);
    res.status(500).json({ message: 'Failed to fetch reviews' });
  }
});

module.exports = router;
