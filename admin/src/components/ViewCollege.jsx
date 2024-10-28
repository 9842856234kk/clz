import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Link } from 'react-router-dom';

const ViewColleges = () => {
  const [colleges, setColleges] = useState([]);

  useEffect(() => {
    const fetchColleges = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/colleges/all');
        setColleges(response.data);
      } catch (error) {
        console.error('Error fetching colleges:', error);
      }
    };
    fetchColleges();
  }, []);

  const handleDelete = async (id) => {
    if (window.confirm('Are you sure you want to delete this college?')) {
      try {
        await axios.delete(`http://localhost:5000/api/colleges/delete/${id}`);
        setColleges((prev) => prev.filter((college) => college.id !== id));
        alert('College deleted successfully');
      } catch (error) {
        console.error('Error deleting college:', error);
        alert('Failed to delete college');
      }
    }
  };

  

  return (
    <div className="max-w-6xl mx-auto my-10 p-6 bg-white">
      <h2 className="text-2xl font-extrabold mb-6 text-gray-800 text-center">Colleges Directory</h2>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
        {colleges.map((college) => (
          <div key={college.id} className="bg-gray-50 border rounded-lg p-6 transition-shadow">
            <div className="mb-4">
              <h3 className="text-xl font-bold text-gray-700">{college.name}</h3>
              <p className="text-gray-600">{college.address}</p>
              <p className="text-gray-600">{college.city}</p>
              <p className="text-gray-600">Courses: {college.courses}</p>
            </div>
            {college.photos && (
              <div className="overflow-hidden rounded-lg mb-4">
                <img 
                  src={`http://localhost:5000/uploads/${college.photos}`} 
                  alt={college.name} 
                  className="w-full h-40 object-cover transform hover:scale-105 transition-transform duration-300" 
                />
              </div>
            )}
            <div className="flex justify-between items-center mt-4">
           <Link to={`/edit-college/${college.id}`}>   <button className="bg-yellow-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-yellow-600 transition-colors"
            
              
              >
                Edit
              </button>
                </Link>
              <button
                onClick={() => handleDelete(college.id)}
                className="bg-red-500 text-white px-4 py-2 rounded-lg font-medium hover:bg-red-600 transition-colors"
              >
                Delete
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};

export default ViewColleges;
