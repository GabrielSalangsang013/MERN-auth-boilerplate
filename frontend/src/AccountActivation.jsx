import { useEffect, useState } from 'react';
import { useParams } from 'react-router-dom';
import { useNavigate } from 'react-router-dom';
import { useDispatch } from 'react-redux';
import { successLoginAction } from './actions/login';
import axios from 'axios';
axios.defaults.withCredentials = true;

const AccountActivation = () => {
    const navigate = useNavigate();
    const { token } = useParams();
    const dispatch = useDispatch();
    const [isActivating, setIsActivating] = useState(false);

    useEffect(() => {
        if(token !== null) {
            axios.post(`http://localhost:4000/api/v1/authentication/activate`, {
                token: token
            })
            .then((response) => {
                if(response.status === 200 && response.data.status === 'ok') {
                    alert('You successfully activate your account');
                    setIsActivating(true);
                    dispatch(successLoginAction())
                    navigate('/');
                }
            })
            .catch(function (error) {
                alert(error.response.data.message);
                navigate('/register');
            })
        }else {
            navigate('/login');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if(!isActivating) {
        return (
            <>
                <h1>Loading</h1>
            </>
        )
    }

    return (
        <>
            <h1>Account Activation Page</h1>
            <p>{token}</p>
        </>
    )
}

export default AccountActivation;