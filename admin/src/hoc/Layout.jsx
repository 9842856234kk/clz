
import { Outlet } from 'react-router-dom';
import AdminPanel from '../components/AdminLanding'; // Adjust the path as necessary

const Layout = () => {
  return (
    <div className="flex min-h-screen bg-gray-50">
      <AdminPanel />
      <div className="flex-1 p-6">
        <Outlet />
      </div>
    </div>
  );
};

export default Layout;