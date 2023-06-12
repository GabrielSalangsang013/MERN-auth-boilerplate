import { useNavigate } from 'react-router-dom';
import { useEffect } from 'react';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const GoogleIdentityServicesSignInButtonWithPrompt = (prop) => {
    const navigate = useNavigate();

    function handleCallbackResponse(response) {
        const sanitizedToken = DOMPurify.sanitize(response.credential);
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/sso/google-identity-services`, {
            token: sanitizedToken
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged in.');
                navigate('/home');
            } 
        })
        .catch(function (error) {
            alert(error.response.data.message);
        });
    }

    useEffect(() => {
        /* global google */
        google.accounts.id.initialize({
            client_id: process.env.REACT_APP_SSO_GOOGLE_IDENITY_SERVICES_CLIENT_ID,
            callback: handleCallbackResponse
        });

        if(prop.addButton === 'True') {
            google.accounts.id.renderButton(
                document.getElementById("signInDiv"),
                {type: 'standard', theme: "filled_black", size:"large", width: '350', logo_alignment: 'center'}
            );
        }
        
        if(prop.addPrompt === 'True') {
            google.accounts.id.prompt();
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <>
            {prop.addButton === 'True' && <div id="signInDiv"></div>}
        </>
    )
}

export default GoogleIdentityServicesSignInButtonWithPrompt;