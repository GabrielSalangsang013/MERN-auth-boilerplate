import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const Home = () => {
    const navigate = useNavigate();
    const [userGoogleAuthenticatorQRCode, setUserGoogleAuthenticatorQRCode] = useState(undefined);

    function handleGetUser(e) {
        e.preventDefault();
        axios.get(`${process.env.REACT_APP_API}/api/v1/authentication/user`)
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                if(response.data.user.googleAuthentication) {
                    if(response.data.user.googleAuthentication.qr_code !== '') {
                        setUserGoogleAuthenticatorQRCode(response.data.user.googleAuthentication.qr_code)
                    }
                }
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
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/logout`)
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

    function handleSuccessfullyScannedQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/delete-google-authenticator-qr-code`, {
           googleAuthenticatorQRCode: userGoogleAuthenticatorQRCode
        })
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully deleted Google Authenticator QR Code.');
                setUserGoogleAuthenticatorQRCode(undefined);
            }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    useEffect(() => {
        axios.get(`${process.env.REACT_APP_API}/api/v1/authentication/user`)
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                if(response.data.user.googleAuthentication) {
                    if(response.data.user.googleAuthentication.qr_code !== '') {
                        setUserGoogleAuthenticatorQRCode(response.data.user.googleAuthentication.qr_code)
                    }
                }
            }
        })
        .catch((error) => {
            alert(error.response.data.message);
            navigate('/login');
        });
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <>
            <button type="button" onClick={handleGetUser}>Get User</button>
            <button type="button" onClick={handleLogout}>Logout</button>  
            {
                userGoogleAuthenticatorQRCode !== undefined && 
                <div>
                    <br/>
                    <div>
                        <img src={userGoogleAuthenticatorQRCode}  alt="User Google Authenticator QR Code"/>
                    </div>
                    <button  type="button" onClick={handleSuccessfullyScannedQRCode}>Successfully Scanned Google Authenticator QR Code</button>
                </div>
            }
        </>
    )
}

export default Home;