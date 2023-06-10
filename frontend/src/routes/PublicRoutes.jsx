import React, { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isAuthenticated, isMFAMode } from '../helpers/auth'; // Import your authentication helper

const PublicRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [authenticated, setAuthenticated] = useState(false);
  const [mfa, setMFA] = useState(false);

  useEffect(() => {
    const checkAuthentication = async () => {
      try {
        const isMFAModeResult = await isMFAMode(); // Assuming this function returns a promise
        const isAuthenticatedResult = await isAuthenticated(); // Assuming this function returns a promise
        setMFA(isMFAModeResult);
        setAuthenticated(isAuthenticatedResult);
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
      }
    };

    checkAuthentication();
  }, []);

  if (loading) {
    return <h1>Loading...</h1>; // or any loading indicator/component
  }

  if (!authenticated && mfa) {
    return <Navigate to="/login/multi-factor-authentication" />
  }

  if(!authenticated && !mfa) {
    return <Outlet />;
  }

  return <Navigate to="/home" />
};

export default PublicRoutes;