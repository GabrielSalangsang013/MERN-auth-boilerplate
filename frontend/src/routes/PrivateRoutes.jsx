import React, { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isAuthenticated } from '../helpers/auth'; // Import your authentication helper
import Loading from '../components/Loading/Loading';

const PrivateRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);

  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const result = await isAuthenticated(); // Assuming this function returns a promise
        setAuthenticated(result);
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
      }
    };

    checkAuthentication();
  }, []);

  if (loading) {
    return  <Loading/>; // or any loading indicator/component
  }

  if (!authenticated) {
    return <Navigate to="/" />;
  }

  const user = authenticated;
  return <Outlet context={[user]}/>;
};

export default PrivateRoutes;