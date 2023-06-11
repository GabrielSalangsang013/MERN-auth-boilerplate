import { useEffect, useState } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import axios from 'axios';

const Home = () => {
    const navigate = useNavigate();
    const [userGoogleAuthenticatorQRCode, setUserGoogleAuthenticatorQRCode] = useState(undefined);
    const [displayButtonGenerateGoogleAuthenticationQRCode, setDisplayButtonGenerateGoogleAuthenticationQRCode] = useState(false);
    const [displayButtonDeleteGoogleAuthenticationQRCode, setDisplayButtonDeleteGoogleAuthenticationQRCode] = useState(false);
    const [user] = useOutletContext();

    function handleGetUser(e) {
        e.preventDefault();
        axios.get(`${process.env.REACT_APP_API}/api/v1/authentication/user`)
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
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/scanned-google-authentication-qr-code`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Scanned Google Authenticator QR Code.');
                setUserGoogleAuthenticatorQRCode(undefined);
                setDisplayButtonDeleteGoogleAuthenticationQRCode(true);
            }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    function handleDeleteGoogleAuthenticationQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/delete-google-authentication-qr-code`)
        .then((response) => {
             if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Deleted Google Authenticator QR Code.');
                setDisplayButtonGenerateGoogleAuthenticationQRCode(true);
                setDisplayButtonDeleteGoogleAuthenticationQRCode(false);
             }
        })
        .catch(function (error) {
             alert(error.response.data.message);
             navigate('/login');
        });
    }

    function handleGenerateGoogleAuthenticationQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/generate-google-authentication-qr-code`)
        .then((response) => {
             if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Generated Google Authenticator QR Code.');
                setUserGoogleAuthenticatorQRCode(response.data.qr_code);
                setDisplayButtonGenerateGoogleAuthenticationQRCode(false);
             }
        })
        .catch(function (error) {
             alert(error.response.data.message);
             navigate('/login');
        });
    }

    useEffect(() => {
        if(!user.hasOwnProperty('googleAuthentication')) {
            setDisplayButtonGenerateGoogleAuthenticationQRCode(true);
        }

        if(user.hasOwnProperty('googleAuthentication') && !user.googleAuthentication.isScanned) {
            setUserGoogleAuthenticatorQRCode(user.googleAuthentication.qr_code);
        }

        if(user.hasOwnProperty('googleAuthentication') && user.googleAuthentication.isScanned) {
            setDisplayButtonDeleteGoogleAuthenticationQRCode(true);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <>
            <button type="button" onClick={handleGetUser}>Get User</button>
            <button type="button" onClick={handleLogout}>Logout</button>
            {
                displayButtonDeleteGoogleAuthenticationQRCode && 
                <button type="button" onClick={handleDeleteGoogleAuthenticationQRCode}>
                    Delete Google Authentication QR Code
                </button>
            }
            {
                displayButtonGenerateGoogleAuthenticationQRCode && 
                <button type="button" onClick={handleGenerateGoogleAuthenticationQRCode}>
                    Generate Google Authentication QR Code
                </button>
            }
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