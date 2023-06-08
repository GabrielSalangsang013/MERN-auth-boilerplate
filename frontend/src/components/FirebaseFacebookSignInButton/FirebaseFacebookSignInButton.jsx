import { authentication } from '../../config/firebase-config';
import { signInWithPopup, FacebookAuthProvider } from "firebase/auth";
import { FacebookLoginButton } from "react-social-login-buttons";

const FirebaseFacebookSignInButton = () => {
    const signInWithFacebook = () => {
        const provider = new FacebookAuthProvider();
        signInWithPopup(authentication, provider)
        .then((response) => {
            console.log(response);
        })
        .catch((error) => {
            console.log(error.message);
        })
    }

    return (
        <>
            <FacebookLoginButton onClick={signInWithFacebook} />
        </>
    )
}

export default FirebaseFacebookSignInButton;