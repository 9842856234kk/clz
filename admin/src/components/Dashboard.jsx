// src/components/Dashboard.jsx
import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';

const Dashboard = () => {
  const [totalColleges, setTotalColleges] = useState(0);

  useEffect(() => {
    const fetchTotalColleges = async () => {
      try {
        const response = await axios.get('http://localhost:5000/api/colleges/all'); // Adjust the endpoint as necessary
        console.log(response.data.length)
        setTotalColleges(response.data.length); // Assuming the response contains a count field
      } catch (error) {
        console.error('Error fetching total colleges:', error);
      }
    };

    fetchTotalColleges();
  }, []);

  return (
    <div className="bg-white p-6 rounded shadow">
      <h1 className="text-2xl font-bold mb-4">Dashboard</h1>
      <p>Welcome to the Admin Dashboard!</p>
      
      <div className="grid grid-cols-3 gap-4 mt-6">
        <div className="bg-blue-100 p-4 rounded shadow">
          <h2 className="font-bold">Total Colleges</h2>
          <p className="text-xl">{totalColleges}</p>
        </div>
       
      </div>

      <div className="mt-6 flex space-x-4">
        <Link to="/add-college" className="bg-blue-500 text-white px-4 py-2 rounded shadow hover:bg-blue-600 transition duration-200">
          Add College
        </Link>
        <Link to="/view-colleges" className="bg-green-500 text-white px-4 py-2 rounded shadow hover:bg-green-600 transition duration-200">
          View Colleges
        </Link>
      </div>
    </div>
  );
};

export default Dashboard;
