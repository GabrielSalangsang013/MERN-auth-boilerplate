import { useEffect, useState } from 'react';
import { useParams } from "react-router-dom";
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
                if(error.response.status === 400 && error.response.data.status === 'fail') {
                    // USER MUST COMPLETE THE REGISTER FORM FIELDS 
                    // MUST PASSED IN THE VALIDATION IN THE BACKEND 
                    // THE USERNAME MUST NOT EXIST OR MUST BE UNIQUE
                    // THE EMAIL MUST NOT EXIST OR MUST BE UNIQUE
                    alert(error.response.data.error);
                    navigate('/register');
                }else if(error.response.status === 401 && error.response.data.status === 'error') {
                    // NO TOKEN
                    navigate('/login');
                }else if(error.response.status === 401 && error.response.data.status === 'fail') {
                    // EXPIRED LINK OR INVALID TOKEN
                    alert(error.response.data.error);
                    navigate('/register');
                }else if(error.response.status === 500 && error.response.data.status === 'error') {
                    // THIS IS AN ERROR FROM THE BACKEND
                    alert(error.response.data.error);
                    navigate('/login');
                }
            })
        }else {
            navigate('/login');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if(!isActivating) {
        return (
            <>
                <h1>Activation link has been sent to your email.</h1>
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