import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';
import { FaStar, FaStarHalfAlt } from 'react-icons/fa'; // Import icons for stars

const CollegeList = () => {
  const [colleges, setColleges] = useState([]);
  const [cities, setCities] = useState([]);
  const [selectedCourse, setSelectedCourse] = useState('');
  const [selectedCity, setSelectedCity] = useState('');
  const [filteredColleges, setFilteredColleges] = useState([]);
  const [loading, setLoading] = useState(false);

  const coursesList = [
    'BBA', 'BCA', 'BHM', 'BIM', 'BIT', 'BBS', 'MBBS',
    'CA', 'B.COM', 'BALLB', 'B.ED', 'BA', 'BSC',
    'BBM','MCA','MBA','MBS','BCS', 'Others'
  ];

  useEffect(() => {
    fetchColleges();
  }, []);

  const fetchColleges = async () => {
    try {
      const response = await axios.get('http://localhost:5000/api/colleges/all');
      setColleges(response.data);
      setFilteredColleges(response.data);
      const cities = [...new Set(response.data.map(college => college.city))];
      setCities(cities);
    } catch (error) {
      console.error('Error fetching colleges:', error);
    }
  };

  const handleFilter = () => {
    setLoading(true);
    const results = colleges.filter(college => {
      const collegeCourses = college.courses.split(',').map(course => course.trim());
      return (
        (selectedCourse ? collegeCourses.includes(selectedCourse) : true) &&
        (selectedCity ? college.city === selectedCity : true)
      );
    });

    const sortedResults = results.sort((a, b) => (b.avg_rating || 0) - (a.avg_rating || 0));
    setFilteredColleges(sortedResults);
    setLoading(false);
  };

  const renderStars = (rating) => {
    const stars = [];
    for (let i = 1; i <= 5; i++) {
      if (i <= Math.floor(rating)) {
        stars.push(<FaStar key={i} className="text-yellow-500" />);
      } else if (i === Math.ceil(rating)) {
        stars.push(<FaStarHalfAlt key={i} className="text-yellow-500" />);
      } else {
        stars.push(<FaStar key={i} className="text-gray-300" />);
      }
    }
    return stars;
  };

  const initialColleges = [...filteredColleges].sort((a, b) => (b.avg_rating || 0) - (a.avg_rating || 0));

  return (
  <div className='bg-blue'>
    <div className="p-8  bg-gradient-to-br from-blue-50 to-blue-100 min-h-screen">
      <h1 className="text-4xl font-bold text-center text-gray-800 mb-8">Explore Colleges</h1>

      <div className="flex justify-center space-x-4 mb-8">
        <select
          value={selectedCourse}
          onChange={e => setSelectedCourse(e.target.value)}
          className="p-3 border border-gray-300 rounded-lg shadow-md focus:ring-2 focus:ring-blue-400"
        >
          <option value="">All Courses</option>
          {coursesList.map((course, index) => (
            <option key={index} value={course}>{course}</option>
          ))}
        </select>

        <select
          value={selectedCity}
          onChange={e => setSelectedCity(e.target.value)}
          className="p-3 border border-gray-300 rounded-lg shadow-md focus:ring-2 focus:ring-blue-400"
        >
          <option value="">All Cities</option>
          {cities.map((city, index) => (
            <option key={index} value={city}>{city}</option>
          ))}
        </select>

        <button
          onClick={handleFilter}
          className="p-3 bg-green-500 text-white rounded-lg shadow-md hover:bg-green-600 transition duration-300"
        >
          Search
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        {(loading ? colleges : initialColleges).map(college => (
          <div key={college.id} className="bg-white rounded-lg shadow-lg overflow-hidden transition-transform transform hover:scale-105 duration-300">
            <img
              src={`http://localhost:5000/uploads/${college.photos}`}
              alt={college.name}
              className="w-full h-48 object-cover"
            />
            <div className="p-5">
              <h2 className="text-2xl font-bold text-gray-800 mb-3">{college.name}</h2>
              <p className="text-gray-600 mb-2"><strong>Address:</strong> {college.address}</p>
              <p className="text-gray-600 mb-2"><strong>City:</strong> {college.city}</p>
              <p className="text-gray-600 mb-2"><strong>Courses:</strong> {college.courses}</p>
              
              <div className="flex items-center mb-2">
                <p className="text-gray-600 mr-2"><strong>Rating:</strong></p>
                <div className="flex">
                  {renderStars(college.avg_rating || 0)}
                </div>
              </div>
              <p className="text-gray-600"><strong>Reviews:</strong> {college.review_count || 0}</p>

              <Link
                to={`/college/${college.id}`}
                className="mt-4 inline-block text-blue-500 hover:underline"
              >
                View Details
              </Link>
            </div>
          </div>
        ))}
      </div>
    </div>
    </div>
  );
};

export default CollegeList;
