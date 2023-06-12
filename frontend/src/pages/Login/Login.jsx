import { useNavigate, Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './Login.module.css';
import FirebaseGoogleSignInButton from '../../components/FirebaseGoogleSignInButton/FirebaseGoogleSignInButton';
import FirebaseFacebookSignInButton from '../../components/FirebaseFacebookSignInButton/FirebaseFacebookSignInButton';
import GoogleIdentityServicesSignInButtonWithPrompt from '../../components/GoogleIdentityServicesSignInButtonWithPrompt/GoogleIdentityServicesSignInButtonWithPrompt';
import logo from '../../assets/logo-header.png';

const Login = () => {
    const navigate = useNavigate();

    const initialValues = {
        username: '',
        password: ''
    };

    const validationSchema = Yup.object().shape({
        username: Yup.string()
            .required('Username is required')
            .trim()
            .min(4, 'Username must be at least 4 characters')
            .max(20, 'Username must not exceed 20 characters')
            .matches(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
            .test(
                'username-security',
                'Username should not contain sensitive information',
                (value) => !/\b(admin|root|superuser)\b/i.test(value)
            )
            .test(
                'username-xss-nosql',
                'Invalid characters detected',
                (value) => {
                    const sanitizedValue = escape(value);
                    return sanitizedValue === value; // Check if sanitized value is the same as the original value
                }
            ),
        password: Yup.string()
            .required('Password is required')
            .min(12, 'Password must be at least 12 characters')
            .matches(
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/,
                'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character'
            )
            .test(
                'password-security',
                'Password should not be commonly used or easily guessable',
                (value) => !/\b(password|123456789)\b/i.test(value)
            )
    });

    const handleSubmit = (values) => {
        const {username, password} = values;
        const sanitizedLoginUsername = DOMPurify.sanitize(username);
        const sanitizedLoginPassword = DOMPurify.sanitize(password);
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/login`, {
            username: sanitizedLoginUsername,
            password: sanitizedLoginPassword
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Multi factor authentication login code has been sent to your email.');
                navigate('/login/multi-factor-authentication');
            } 
        })
        .catch(function (error) {
            alert(error.response.data.message);
        });
    };

    return (
        <>
            <div className={`${style.container}`}>
                
                <header className={`${style.header}`}>
                    <div className={`${style.logo_container}`}>
                        <Link to='/' className={`${style.link}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </Link>
                    </div>
                    <div className={`${style.nav_links}`}>
                        <Link to='/register' className={`${style.link}`}>Register</Link>
                    </div>
                </header>
                
                
                <main className={`${style.main}`}>
                    <div className={`${style.login_form}`}>
                    <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                        <Form>
                            <h1 className={`${style.login_form_title}`}>Welcome to Login</h1>
                            <p className={`${style.login_form_subtitle}`}>Enter your username and password to login</p>

                            <Field className={`${style.login_form_input}`} placeholder='Enter your username' type="text" id="username" name="username"/>
                            <ErrorMessage name="username" component="div" className={`${style.login_form_input_error}`}/>
                            <Field className={`${style.login_form_input}`} placeholder='Enter your password' type="password" id="password" name="password"/>
                            <ErrorMessage name="password" component="div" className={`${style.login_form_input_error}`}/>    
                            <button className={`${style.login_form_submit}`} type="submit">Sign In</button>
                        
                            <Link className={`${style.login_form_link_forgot_password}`} to="/forgot-password">Forgot password?</Link>
                            
                            <div className={`${style.overline_container}`}>
                                <div className={`${style.overline}`}></div>
                                <div className={`${style.overline_text}`}>
                                    <span>OR CONTINUE WITH</span>
                                </div>
                            </div>

                            <GoogleIdentityServicesSignInButtonWithPrompt addButton="True" addPrompt="True"/> 
                            <FirebaseFacebookSignInButton />
                            <FirebaseGoogleSignInButton />
                        </Form>
                    </Formik>
                    </div>
                </main>
                
            </div>
        </>
    )
}

export default Login;