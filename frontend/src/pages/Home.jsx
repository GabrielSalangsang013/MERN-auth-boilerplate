import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Home = () => {
    const navigate = useNavigate();

    function handleGetUser(e) {
        e.preventDefault();
        axios.get('http://localhost:4000/api/v1/authentication/user')
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                console.log(response);
            }
        })
        .catch((error) => {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    function handleLogout(e) {
        e.preventDefault();
        axios.post('http://localhost:4000/api/v1/authentication/logout')
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged out.');
                navigate('/login');
            }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    return (
        <>
            <button type='button' onClick={handleGetUser}>Get User</button>
            <button type='button' onClick={handleLogout}>Logout</button>  
        </>
    )
}

export default Home;