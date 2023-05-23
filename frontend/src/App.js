import React from 'react'
import { useEffect, useState } from 'react';
import {Route, Routes, useNavigate} from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { successLoginAction, failLoginAction } from './actions/login';
import Home from './Home';
import Login from './Login';
import Register from './Register';
import axios from 'axios'

function App() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const [isAuthenticating, setIsAuthenticating] = useState(true);

  useEffect(() => {
    axios.get('http://localhost:4000/api/v1/authentication/user')
      .then((response) => {
        if(response.status === 200 && response.data.status === 'ok') {
          navigate('/')
          dispatch(successLoginAction());
          setIsAuthenticating(false);
        }
      })
      .catch((error) => {
        if(error.response.status === 401 && error.response.data.status === 'error') {
          // UNAUTHORIZED USER
          alert(error.response.data.error)
        }else if(error.response.status === 403  && error.response.data.status === 'error') {
          // FORBIDDEN OR INVALID TOKEN
          alert(error.response.data.error)
        }else if(error.response.status === 500 && error.response.data.status === 'error') {
          // THIS IS AN ERROR FROM THE BACKEND
          alert(error.response.data.error);
        }

        if(!(window.location.href.indexOf('register') > -1)) {
          navigate('/login')
        }

        setIsAuthenticating(false);
        dispatch(failLoginAction());
      })
  }, []);

  if (isAuthenticating) {
    return (
    <>
      <h1>Loading</h1>
    </>);
  }

  return (
    <div>      
      <Routes>
          <Route path='/' exact element={<Home />}/>
          <Route path='/login' exact element={<Login />}/>
          <Route path='/register' exact element={<Register />}/>
      </Routes>
    </div>
  )
}

export default App
