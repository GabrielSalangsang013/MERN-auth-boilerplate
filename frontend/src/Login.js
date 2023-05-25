import { useState } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { successLoginAction } from './actions/login';
import { useNavigate } from 'react-router-dom';
import axios from 'axios'
axios.defaults.withCredentials = true

const Login = () => {
    const navigate = useNavigate();
    const isAuthenticated = useSelector((state) => state.isAuthenticated);
    const dispatch = useDispatch();
    const [loginUsername, setLoginUsername] = useState('')
    const [loginPassword, setLoginPassword] = useState('')

    function handleLogin(e) {
        e.preventDefault()
        axios.post('http://localhost:4000/api/v1/authentication/login', {
            username: loginUsername,
            password: loginPassword
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged in.')
                dispatch(successLoginAction())
                navigate('/');
            } 
        })
        .catch(function (error) {
            if(error.response.status === 401 && error.response.data.status === 'fail') {
                // INVALID INPUT LOGIN FORM
                alert(error.response.data.error)
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error)
            }
        })
    }

    return (
        <>
            <h2>Login Form</h2>
            <input type='text' placeholder='Enter username' onChange={e => setLoginUsername(e.target.value)} />
            <input type='password' placeholder='Enter password' onChange={e => setLoginPassword(e.target.value)} />
            <button type='submit' onClick={handleLogin}>Login</button>
            {isAuthenticated ? <h3>You are logged in</h3> : <h3>You are not logged in</h3>}
        </>
    )
}

export default Login;