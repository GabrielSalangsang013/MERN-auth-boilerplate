import React, { useEffect, useState } from 'react';
import { Navigate, Outlet } from 'react-router-dom';
import { isMFAMode } from '../helpers/auth'; // Import your authentication helper
import Loading from '../components/Loading/Loading';

const PublicRoutes = () => {
  const [loading, setLoading] = useState(true);
  const [mfaMode, setMFAMode] = useState(false);

  useEffect(() => {
    const checkIfMFAMode = async () => {
      try {
        const result = await isMFAMode(); // Assuming this function returns a promise
        setMFAMode(result);
        setLoading(false);
      } catch (error) {
        // Handle any error that occurred during authentication
      }
    };

    checkIfMFAMode();
  }, []);

  if (loading) {
    return <Loading />; // or any loading indicator/component
  }

  if (mfaMode) {
    const user = mfaMode;
    return <Outlet context={[user]}/> ;
  }

  return <Navigate to="/" />
};

export default PublicRoutes;