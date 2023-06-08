import { authentication } from '../../config/firebase-config';
import { signInWithPopup, GoogleAuthProvider } from "firebase/auth";
import { GoogleLoginButton } from "react-social-login-buttons";

const FirebaseGoogleSignInButton = () => {
    const signInWithGoogle = () => {
        const provider = new GoogleAuthProvider();
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
            <GoogleLoginButton onClick={signInWithGoogle} />
        </>
    )
}

export default FirebaseGoogleSignInButton;