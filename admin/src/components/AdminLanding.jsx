
import { FaUniversity, FaListAlt } from 'react-icons/fa';
import { MdDashboard } from "react-icons/md";
import { Link } from 'react-router-dom';

const AdminPanel = () => {
  return (
    <aside className="w-64 bg-blue-600 text-white"> {/* You can adjust this width */}
      <div className="p-6">
        <h2 className="text-3xl font-bold mb-4">Admin Panel</h2>
        <nav>
          <ul>
            <li className="mb-3 flex items-center p-3 rounded-md hover:bg-blue-500">
              <Link to="/" className="flex items-center w-full">
                <MdDashboard className="mr-3" />
                <span>Dashboard</span>
              </Link>
            </li>
            <li className="mb-3 flex items-center p-3 rounded-md hover:bg-blue-500">
              <Link to="/add-college" className="flex items-center w-full">
                <FaUniversity className="mr-3" />
                <span>Add College</span>
              </Link>
            </li>
            <li className="mb-3 flex items-center p-3 rounded-md hover:bg-blue-500">
              <Link to="/view-colleges" className="flex items-center w-full">
                <FaListAlt className="mr-3" />
                <span>View Colleges</span>
              </Link>
            </li>
          </ul>
        </nav>
      </div>
    </aside>
  );
};

export default AdminPanel;
