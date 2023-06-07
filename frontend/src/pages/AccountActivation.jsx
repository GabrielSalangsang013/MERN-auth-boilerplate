import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';

const AccountActivation = () => {
    const navigate = useNavigate();
    const { token } = useParams();
    const [isActivated, setIsActivated] = useState(false);

    useEffect(() => {
        if(token !== null) {
            axios.post(`${process.env.REACT_APP_API_KEY}/api/v1/authentication/activate`, {
                token: token
            })
            .then((response) => {
                if(response.status === 200 && response.data.status === 'ok') {
                    alert('You successfully activate your account');
                    setIsActivated(true);
                    navigate('/home');
                }
            })
            .catch(function (error) {
                alert(error.response.data.message);
                navigate('/register');
            })
        }else {
            navigate('/');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if(!isActivated) {
        return (
            <>
                <h1>Loading...</h1>
            </>
        )
    }
}

export default AccountActivation;