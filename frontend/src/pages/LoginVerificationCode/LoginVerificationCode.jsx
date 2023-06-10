import { useState, useEffect } from 'react';
import { useNavigate, useOutletContext  } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const LoginVerificationCode = () => {
    const navigate = useNavigate();
    const [showButtonDisplayGoogleAuthenticationForm, setShowButtonDisplayGoogleAuthenticationForm] = useState(false);
    const [useGoogleAuthenticationForm, setUseGoogleAuthenticationForm] = useState(false);
    const [user] = useOutletContext();

    const initialValues = {
        verificationCodeLogin: ''
    };

    const initialValuesGoogleAuthentication = {
        googleAuthenticationCodeLogin: ''
    };

    const validationSchema = Yup.object().shape({
        verificationCodeLogin: Yup.string()
            .required('Verification login code is required')
            .min(7, 'Verification login code must be 7 characters')
            .max(7, 'Verification login code must be 7 characters')
            .matches(/^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/, 'Verification login code must be 7 characters and contain only numbers and letters')
            .test(
                'verificationCodeLogin', 
                'Verification login code should not contain sensitive information', 
                value => {
                    return !/\b(admin|root|superuser)\b/i.test(value);
                }
            )
            .test(
                'verificationCodeLogin', 
                'Invalid verification login code format or potentially unsafe characters', 
                value => {
                    const sanitizedValue = escape(value);
                    return sanitizedValue === value;
                }
            )
    });

    const validationSchemaGoogleAuthentication = Yup.object().shape({
        googleAuthenticationCodeLogin: Yup.string()
            .required('Google Authentication Code Login is required')
            .matches(/^\d{6}$/, 'Code must be a 6-digit number'),
    });

    const handleSubmit = (values) => {
        const {verificationCodeLogin} = values;
        const sanitizedVerificationCodeLogin = DOMPurify.sanitize(verificationCodeLogin);
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/verification-code-login`, {
            verificationCodeLogin: sanitizedVerificationCodeLogin
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
    };

    const handleSubmitGoogleAuthentication = (values) => {
        const {googleAuthenticationCodeLogin} = values;
        const sanitizedGoogleAuthenticationCodeLogin = DOMPurify.sanitize(googleAuthenticationCodeLogin);
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/google-authentication-code-login`, {
            googleAuthenticationCodeLogin: sanitizedGoogleAuthenticationCodeLogin
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

    const handleLogout = () => {
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/verification-code-login/logout`)
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged out.');
                navigate('/login');
            } 
        })
        .catch(function (error) {
            alert(error.response.data.message);
        });
    }

    const switchFormToGoogleAuthenticationForm = () => {
        setUseGoogleAuthenticationForm(true);
    }

    const switchSendVerificationCodeForm = () => {
        setUseGoogleAuthenticationForm(false);
    }
    
    useEffect(() => {
        if(user.hasGoogleAuthentication) {
            setShowButtonDisplayGoogleAuthenticationForm(true);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    return (
        <>
            { !useGoogleAuthenticationForm && 
            <>
                <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                    <Form>
                        <h1>Multi Factor Authencation Login Code Form</h1>
                        <div>
                            <img src={user.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                        </div>
                        <br/>
                        <div>
                            <label htmlFor="verificationCodeLogin">Verification Code: </label>
                            <Field type="text" id="verificationCodeLogin" name="verificationCodeLogin" autoComplete="off" />
                            <ErrorMessage name="verificationCodeLogin" component="div" />
                        </div>
                        <br/>
                        <button type="submit">Send Code</button>
                        <button type="button" onClick={handleLogout}>Logout</button>
                        <br/><br/>
                        { showButtonDisplayGoogleAuthenticationForm && <button type="button" onClick={switchFormToGoogleAuthenticationForm}>Use Google Authenticator</button>}
                    </Form>
                </Formik>
            </>
            }
            { useGoogleAuthenticationForm && 
            <> 
                <Formik initialValues={initialValuesGoogleAuthentication} validationSchema={validationSchemaGoogleAuthentication} onSubmit={handleSubmitGoogleAuthentication}>
                    <Form>
                        <h1>Multi Factor Authencation Login Code Form - Google Authentication</h1>
                        <div>
                            <img src={user.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                        </div>
                        <br/>
                        <div>
                            <label htmlFor="googleAuthenticationCodeLogin">Enter Google Authentication Code: </label>
                            <Field type="text" id="googleAuthenticationCodeLogin" name="googleAuthenticationCodeLogin" autoComplete="off" />
                            <ErrorMessage name="googleAuthenticationCodeLogin" component="div" />
                        </div>
                        <br/>
                        <button type="submit">Send Code</button>
                        <button type="button" onClick={handleLogout}>Logout</button>
                        <br/><br/>
                        <button type="button" onClick={switchSendVerificationCodeForm}>Send Verification Code</button>
                    </Form>
                </Formik>
            </>
            }
        </>
    )
}

export default LoginVerificationCode;