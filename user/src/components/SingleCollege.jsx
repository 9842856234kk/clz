import  { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';
import RatingPage from './RatingPage';

const SingleCollege = () => {
    const { id } = useParams();
    const navigate = useNavigate();
    const [college, setCollege] = useState(null);
    const [showReviewForm, setShowReviewForm] = useState(false);
    const [reviewData, setReviewData] = useState({ rating: 0, comment: '' });
    const [error, setError] = useState(null);
    const [hasReviewed, setHasReviewed] = useState(false);

    const customerID = localStorage.getItem('studentID');
    const token = localStorage.getItem('token1');

    useEffect(() => {
        fetchCollege();
        checkExistingReview();
    }, [id]);

    const fetchCollege = async () => {
        try {
            const response = await axios.get(`http://localhost:5000/api/colleges/single/${id}`);
            setCollege(response.data.college);
        } catch (error) {
            console.error('Error fetching college:', error);
        }
    };

    const checkExistingReview = async () => {
        try {
            const response = await axios.get(`http://localhost:5000/api/review/check/${id}/${customerID}`);
            if (response.data.hasReviewed) {
                setHasReviewed(true);
            }
        } catch (error) {
            console.error('Error checking review:', error);
        }
    };

    const handleAddReview = () => {
        if (!token || !customerID) {
            navigate('/login');
        } else {
            setShowReviewForm(true);
        }
    };

    const handleReviewChange = (e) => {
        setReviewData({ ...reviewData, [e.target.name]: e.target.value });
    };

    const handleStarClick = (rating) => {
        setReviewData({ ...reviewData, rating });
    };

    const handleSubmitReview = async (e) => {
        e.preventDefault();

        try {
            await axios.post(`http://localhost:5000/api/review/rate/${id}`, {
                studentId: customerID,
                rating: reviewData.rating,
                comment: reviewData.comment,
            });

            setShowReviewForm(false);
            setReviewData({ rating: 0, comment: '' });
            location.reload();
        } catch (error) {
            setError('Error submitting review');
            console.error(error);
        }
    };

    if (!college) return <div className="text-center mt-10 text-lg font-semibold">Loading...</div>;

    return (
        <div className="p-6 bg-gradient-to-br from-blue-50 to-blue-100 min-h-screen">
            <div className="max-w-7xl mx-auto bg-white rounded-lg shadow-lg overflow-hidden">
                <div className="text-center p-6 bg-blue-600 text-white">
                    <h1 className="text-4xl font-bold">{college.name}</h1>
                    <p className="text-xl mt-2">{college.city}</p>
                </div>
                <div className="p-6">
                    <img
                        src={`http://localhost:5000/uploads/${college.photos}`}
                        alt={`${college.name}`}
                        className="mx-auto mb-6 w-full h-72 object-cover rounded-lg shadow-lg"
                    />
                    <p className="text-center text-lg mb-2">{college.address}</p>
                    <p className="text-center text-lg font-medium">Courses Offered: {college.courses.split(',').join(', ')}</p>

                    {!hasReviewed ? (
                        <>
                            <div className="flex justify-center mt-8">
                                <button
                                    onClick={handleAddReview}
                                    className="bg-gradient-to-r from-blue-500 to-green-500 hover:from-blue-600 hover:to-green-600 text-white font-semibold py-2 px-6 rounded-full shadow-lg transition-all duration-300"
                                >
                                    Add Review
                                </button>
                            </div>

                            {showReviewForm && (
                                <form className="mt-8 p-6 bg-gray-50 border rounded-lg shadow-md" onSubmit={handleSubmitReview}>
                                    <h2 className="text-2xl font-bold text-center mb-4">Submit Your Review</h2>

                                    <div className="mb-4">
                                        <label className="block text-lg font-medium text-gray-700">Rating (out of 5)</label>
                                        <StarRating rating={reviewData.rating} onRatingClick={handleStarClick} />
                                    </div>

                                    <div className="mb-4">
                                        <label className="block text-lg font-medium text-gray-700">Comment</label>
                                        <textarea
                                            name="comment"
                                            value={reviewData.comment}
                                            onChange={handleReviewChange}
                                            className="mt-1 block w-full p-3 border rounded-lg shadow-sm focus:ring focus:ring-blue-200"
                                            required
                                        ></textarea>
                                    </div>

                                    {error && <p className="text-red-500 text-center mb-4">{error}</p>}

                                    <div className="flex justify-center">
                                        <button
                                            type="submit"
                                            className="bg-green-500 hover:bg-green-600 text-white font-bold py-2 px-6 rounded-full shadow-lg transition-all duration-300"
                                        >
                                            Submit Review
                                        </button>
                                    </div>
                                </form>
                            )}
                        </>
                    ) : (
                        <p className="text-center mt-8 text-red-500 font-semibold text-lg">You have already submitted a review for this college.</p>
                    )}

                    <RatingPage collegeId={id} />
                </div>
            </div>
        </div>
    );
};

export default SingleCollege;

const StarRating = ({ rating, onRatingClick }) => {
    const [hover, setHover] = useState(0);

    return (
        <div className="flex space-x-2 justify-center mt-2">
            {[...Array(5)].map((star, index) => {
                index += 1;
                return (
                    <button
                        key={index}
                        type="button"
                        className={`text-3xl ${index <= (hover || rating) ? 'text-yellow-500' : 'text-gray-300'}`}
                        onClick={() => onRatingClick(index)}
                        onMouseEnter={() => setHover(index)}
                        onMouseLeave={() => setHover(rating)}
                    >
                        &#9733;
                    </button>
                );
            })}
        </div>
    );
};
