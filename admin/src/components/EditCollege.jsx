import { useEffect, useState } from 'react';
import axios from 'axios';
import { useParams, useNavigate } from 'react-router-dom';

const coursesList = ['BBA', 'BCA', 'BHM', 'BIM', 'BIT', 'MBA' ,'MCA','BA', 'MBS', 'BALLB', 'BSC', 'BBS', 'B.ED', 'BSC.CSIT', 'MBBS', 'Others'];

const EditCollege = () => {
  const { id } = useParams(); // Get the college ID from the URL
  const navigate = useNavigate();

  const [formData, setFormData] = useState({
    name: '',
    address: '',
    city: '',
    courses: [],
    photo: null,
  });

  useEffect(() => {
    const fetchCollegeDetails = async () => {
      try {
        const response = await axios.get(`http://localhost:5000/api/colleges/single/${id}`);
        console.log(response.data); // Log the entire response
        const collegeData = response.data.college; // Access the college object directly
        setFormData({
          name: collegeData.name,
          address: collegeData.address,
          city: collegeData.city,
          courses: collegeData.courses.split(','), // Assuming courses are a comma-separated string
          photo: collegeData.photo, // Set the initial photo if necessary
        });
      } catch (error) {
        console.error('Error fetching college details:', error);
      }
    };
    fetchCollegeDetails();
  }, [id]);

  const handleChange = (e) => {
    const { name, value, type, files } = e.target;
    if (type === 'checkbox') {
      const checked = e.target.checked;
      setFormData((prev) => ({
        ...prev,
        courses: checked
          ? [...prev.courses, value]
          : prev.courses.filter((course) => course !== value),
      }));
    } else {
      setFormData((prev) => ({
        ...prev,
        [name]: type === 'file' ? files[0] : value,
      }));
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    const formDataToSubmit = new FormData();
    for (let key in formData) {
      formDataToSubmit.append(key, formData[key]);
    }

    try {
      await axios.put(`http://localhost:5000/api/colleges/update/${id}`, formDataToSubmit, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      alert('College updated successfully');
      navigate('/'); // Redirect back to the college list
    } catch (error) {
      console.error('Error updating college:', error);
      alert('Failed to update college');
    }
  };

  return (
    <div className="max-w-5xl mx-auto my-10 p-5 border rounded shadow-lg">
      <h2 className="text-lg font-bold mb-4">Edit College</h2>
      <form onSubmit={handleSubmit}>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">Name</label>
          <input
            type="text"
            name="name"
            value={formData.name}
            onChange={handleChange}
            required
            className="w-full border rounded p-2"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">Address</label>
          <input
            type="text"
            name="address"
            value={formData.address}
            onChange={handleChange}
            required
            className="w-full border rounded p-2"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">City</label>
          <input
            type="text"
            name="city"
            value={formData.city}
            onChange={handleChange}
            required
            className="w-full border rounded p-2"
          />
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">Courses</label>
          {coursesList.map((course) => (
            <div key={course} className="flex items-center mb-2">
              <input
                type="checkbox"
                name="courses"
                value={course}
                checked={formData.courses.includes(course)} // Pre-select courses
                onChange={handleChange}
                className="mr-2"
              />
              <label className="text-sm">{course}</label>
            </div>
          ))}
        </div>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">Upload Photo</label>
          <input
            type="file"
            name="photo"
            onChange={handleChange}
            className="border rounded p-2"
          />
        </div>
        <button type="submit" className="bg-blue-500 text-white px-4 py-2 rounded">
          Update
        </button>
      </form>
    </div>
  );
};

export default EditCollege;
