import { useState, useEffect } from 'react';
import { useNavigate, useOutletContext  } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './LoginVerificationCode.module.css';
import logo from '../../assets/logo-header.png';

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
                <div className={`${style.container}`}>
                    <header className={`${style.header}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            <img className={`${style.profile_picture}`} src={user.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                            <span onClick={handleLogout} className={`${style.link}`}>Logout</span>
                        </div>
                    </header>
                    
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.login_verification_code_form}`}>
                        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                            <Form>
                                <h1 className={`${style.login_verification_code_form_title}`}>MFA - Login Code</h1>
                                <p className={`${style.login_verification_code_form_subtitle}`}>Please enter your login code to verify</p>

                                <Field className={`${style.login_verification_code_form_input}`} type="text" id="verificationCodeLogin" placeholder='Enter your verification code login' name="verificationCodeLogin" autoComplete="off" />
                                <ErrorMessage name="verificationCodeLogin" component="div" className={`${style.login_verification_code_form_input_error}`}/>

                                <button className={`${style.login_verification_code_form_submit}`} type="submit">Submit</button>
                                { showButtonDisplayGoogleAuthenticationForm && 
                                <>
                                    <button onClick={switchFormToGoogleAuthenticationForm} className={`${style.button_dark}`} type="button">
                                        Use Google Authenticator
                                    </button>
                                </>}
                            </Form>
                        </Formik>
                        </div>
                    </main>
                </div>
            </>
            } 

            { useGoogleAuthenticationForm && 
            <> 
                <div className={`${style.container}`}>
                    <header className={`${style.header}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            <img className={`${style.profilePicture}`} src={user.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                            <span onClick={handleLogout} className={`${style.link}`}>Logout</span>
                        </div>
                    </header>
                    
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.login_verification_code_form}`}>
                        <Formik initialValues={initialValuesGoogleAuthentication} validationSchema={validationSchemaGoogleAuthentication} onSubmit={handleSubmitGoogleAuthentication}>
                            <Form>
                                <h1 className={`${style.login_verification_code_form_title}`}>Google Authentication Code</h1>
                                <p className={`${style.login_verification_code_form_subtitle}`}>Please enter your 6-digit code to verify</p>

                                <Field className={`${style.login_verification_code_form_input}`} type="text" id="googleAuthenticationCodeLogin" placeholder='Enter your 6-digit code login' name="googleAuthenticationCodeLogin" autoComplete="off" />
                                <ErrorMessage name="googleAuthenticationCodeLogin" component="div" className={`${style.login_verification_code_form_input_error}`}/>

                                <button className={`${style.login_verification_code_form_submit}`} type="submit">Submit</button>
                                { showButtonDisplayGoogleAuthenticationForm && 
                                <>
                                    <button onClick={switchSendVerificationCodeForm} className={`${style.button_dark}`} type="button">
                                       Send Verification Code
                                    </button>
                                </>}
                            </Form>
                        </Formik>
                        </div>
                    </main>
                </div>
            </>
            }
        </>
    )
}

export default LoginVerificationCode;