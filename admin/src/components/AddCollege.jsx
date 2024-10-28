import React, { useState } from 'react';
import axios from 'axios';

const coursesList = ['BBA', 'BCA', 'BHM', 'BIM', 'BIT', 'MBA' ,'BCS','MCA','BA','CA','B.COM','BBM','Nursing', 'MBS', 'BALLB', 'BSC', 'BBS', 'B.ED', 'BSC.CSIT', 'MBBS', 'Others'];

const AddCollege = () => {
  const [formData, setFormData] = useState({
    name: '',
    address: '',
    city: '',
    courses: [],
    photo: null,
  });

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
      await axios.post('http://localhost:5000/api/colleges/add', formDataToSubmit, {
        headers: {
          'Content-Type': 'multipart/form-data',
        },
      });
      alert('College added successfully');
    } catch (error) {
      console.error('Error adding college:', error);
      alert('Failed to add college');
    }
  };

  return (
    <div className="max-w-5xl my-10 p-5 border rounded shadow-lg">
      <h2 className="text-lg font-bold mb-4">Add College</h2>
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
          Submit
        </button>
      </form>
    </div>
  );
};

export default AddCollege;
