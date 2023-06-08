import { useNavigate } from 'react-router-dom';
import { authentication } from '../../config/firebase-config';
import { signInWithPopup, FacebookAuthProvider } from "firebase/auth";
import { FacebookLoginButton } from "react-social-login-buttons";
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const FirebaseFacebookSignInButton = () => {
    const navigate = useNavigate();

    const signInWithFacebook = () => {
        const provider = new FacebookAuthProvider();
        signInWithPopup(authentication, provider)
        .then((response) => {
            const sanitizedToken = DOMPurify.sanitize(response.user.accessToken);
            axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/sso/firebase-facebook`, {
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
        })
        .catch((error) => {
            console.log(error.message);
        });
    }

    return (
        <>
            <FacebookLoginButton onClick={signInWithFacebook} />
        </>
    )
}

export default FirebaseFacebookSignInButton;