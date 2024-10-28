import React, { useEffect, useState } from 'react';
import axios from 'axios';

const RatingPage = ({ collegeId }) => {
  const [reviews, setReviews] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  // Fetch reviews from API
  useEffect(() => {
    const fetchReviews = async () => {
      try {
        const response = await axios.get(`http://localhost:5000/api/review/${collegeId}`); // Adjust API path as needed
        console.log(response.data);
        setReviews(response.data);
        setLoading(false);
      } catch (error) {
        if (error.response && error.response.status === 404) {
          setError('No reviews found for this college.');
        } else {
          setError('Error fetching reviews');
        }
        setLoading(false);
      }
    };

    if (collegeId) {
      fetchReviews();
    }
  }, [collegeId]);

  if (loading) return <p>Loading...</p>;
  if (error) return <p>{error}</p>;

  return (
    <div className="container mx-auto p-4">
      <h1 className="text-3xl font-bold mb-4">User Reviews</h1>
      <div className="space-y-4">
        {reviews.length > 0 ? (
          reviews.map((review, index) => (
            <div
              key={index}
              className="border p-4 rounded shadow-md bg-white hover:shadow-lg transition duration-300"
            >
              <p className="text-xl font-semibold">Rating: {review.rating} / 5</p>
              <p className="italic">"{review.comments}"</p>
            </div>
          ))
        ) : (
          <p>No reviews available</p>
        )}
      </div>
    </div>
  );
};

export default RatingPage;
