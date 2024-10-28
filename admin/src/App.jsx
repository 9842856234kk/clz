import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';
// import AdminPanel from './components/AdminLanding';
import EditCollege from './components/EditCollege';
import AddCollege from './components/AddCollege';
import ViewColleges from './components/ViewCollege';
import Dashboard from './components/Dashboard';
import Layout from './hoc/Layout';

const App = () => {
  return (
   
    <Router>
      <Routes>
        <Route element={<Layout />}>
        
          <Route index element={<Dashboard />} />
         <Route path="/add-college" element={<AddCollege />} />
        <Route path="/view-colleges" element={<ViewColleges />} />
        <Route path="/edit-college/:id" element={<EditCollege />} />
        
        </Route>
      </Routes>
   </Router>
  );
};

export default App;
