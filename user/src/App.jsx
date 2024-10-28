import { BrowserRouter as Router, Route, Routes } from 'react-router-dom';
import CollegeList from './components/CollegeList';
import SingleCollege from './components/SingleCollege';
import Navbar from './components/Navbar';
import Login from './auth/Login';
import { AuthProvider } from './auth/AuthContext'; // Adjust the path as necessary
import Signup from './auth/Signup';


const App = () => {
  return (
    <AuthProvider>
      <Router>
        <div className="bg-gray-100 min-h-screen">
          <Navbar />
          <Routes>
            <Route path="/" element={<CollegeList />} />
            <Route path="/college/:id" element={<SingleCollege />} />
            <Route path='/login' element={<Login />} />
            <Route path='/signup' element={<Signup />} />
         </Routes>
        </div>
      </Router>
    </AuthProvider>
  );
};

export default App;
