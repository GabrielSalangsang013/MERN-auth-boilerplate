import axios from 'axios';

export const isAuthenticated = async () => {
  try {
    const response = await axios.get('http://localhost:4000/api/v1/authentication/user');
    if (response.status === 200 && response.data.status === 'ok') return true;
    return false;
  } catch (error) {
    return false;
  }
};