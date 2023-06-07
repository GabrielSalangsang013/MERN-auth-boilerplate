import axios from 'axios';

export const isAuthenticated = async () => {
  try {
    const response = await axios.get(`${process.env.REACT_APP_API_KEY}/api/v1/authentication/user`);
    if (response.status === 200 && response.data.status === 'ok') return true;
    return false;
  } catch (error) {
    return false;
  }
};

export const isMFAMode = async () => {
  try {
    const response = await axios.get(`${process.env.REACT_APP_API_KEY}/api/v1/authentication/user`);
    if (response.status === 200 && response.data.status === 'MFA-Mode') return response.data.user;
    return false;
  } catch (error) {
    return false;
  }
};