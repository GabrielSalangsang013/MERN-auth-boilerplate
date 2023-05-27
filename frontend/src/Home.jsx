import { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { failLoginAction } from './actions/login';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
axios.defaults.withCredentials = true;

const Home = () => {
    const navigate = useNavigate();
    const isAuthenticated = useSelector((state) => state.isAuthenticated);
    const dispatch = useDispatch();

    function handleGetUser(e) {
        e.preventDefault();
        axios.get('http://localhost:4000/api/v1/authentication/user')
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                console.log(response);
            }
        })
        .catch((error) => {
            if(error.response.status === 401 && error.response.data.status === 'error') {
                // UNAUTHORIZED USER
                alert(error.response.data.error);
            }else if(error.response.status === 403  && error.response.data.status === 'error') {
                // FORBIDDEN OR INVALID TOKEN
                alert(error.response.data.error);
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error);
            }

            dispatch(failLoginAction());
            navigate('/login');
        });
    }

    function handleLogout(e) {
        e.preventDefault();
        axios.post('http://localhost:4000/api/v1/authentication/logout')
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged out.');
                dispatch(failLoginAction());
                navigate('/login');
            }
        })
        .catch(function (error) {
            if(error.response.status === 401 && error.response.data.status === 'error') {
                // UNAUTHORIZED USER
                alert(error.response.data.error);
            }else if(error.response.status === 403  && error.response.data.status === 'error') {
                // FORBIDDEN OR INVALID TOKEN
                alert(error.response.data.error);
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error);
            }

            dispatch(failLoginAction());
            navigate('/login');
        });
    }

    useEffect(() => {
		if(!isAuthenticated) {
            navigate('/login');
        }
	}, [])

    return (
        <>
            <button type='button' onClick={handleGetUser}>Get User</button>
            <button type='button' onClick={handleLogout}>Logout</button>  
            {isAuthenticated ? <h3>You are logged in</h3> : <h3>You are not logged in</h3>}
        </>
    )
}

export default Home;