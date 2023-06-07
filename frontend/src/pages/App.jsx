import React from 'react';
import { Link } from 'react-router-dom';
import axios from 'axios';
axios.defaults.withCredentials = true;

function App() {
  return (
    <>
      <div>      
        <h1>Welcome to the landing page</h1>
        |&nbsp;  <Link to='/login'>Login</Link> |&nbsp; 
        <Link to='/register'>Register</Link>
      </div>
    </>
  )
}

export default App
