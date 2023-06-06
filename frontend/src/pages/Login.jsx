import { useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const Login = () => {
    const navigate = useNavigate();
    const [requestLoginCode, setRequestLoginCode] = useState(false);

    const initialValues = {
        username: '',
        password: '',
        verificationCodeLogin: ''
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

    const validationSchemaVerificationCodeLogin = Yup.object().shape({
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

    const handleSubmit = (values) => {
        const {username, password} = values;
        const sanitizedLoginUsername = DOMPurify.sanitize(username);
        const sanitizedLoginPassword = DOMPurify.sanitize(password);
        axios.post('http://localhost:4000/api/v1/authentication/login', {
            username: sanitizedLoginUsername,
            password: sanitizedLoginPassword
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Two factor authentication login code has been sent to your email.');
                setRequestLoginCode(true);
            } 
        })
        .catch(function (error) {
            alert(error.response.data.message);
        });
    };

    const handleSubmitVerificationCodeLogin = (values) => {
        const {verificationCodeLogin} = values;
        const sanitizedVerificationCodeLogin = DOMPurify.sanitize(verificationCodeLogin);
        axios.post('http://localhost:4000/api/v1/authentication/verification-code-login', {
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

    if(requestLoginCode) {
        return (
            <>
                <Formik 
                    initialValues={initialValues} 
                    validationSchema={validationSchemaVerificationCodeLogin} 
                    onSubmit={handleSubmitVerificationCodeLogin}
                    >

                    <Form>
                        <h1>Two Factor Authencation Login Code Form</h1>

                        <div>
                            <label htmlFor="verificationCodeLogin">Verification Code: </label>
                            <Field type="text" id="verificationCodeLogin" name="verificationCodeLogin" autoComplete="off" />
                            <ErrorMessage name="verificationCodeLogin" component="div" />
                        </div>
                        
                        <br/>

                        <button type="submit">Send Code</button>
                    </Form>
                </Formik>
            </>
        )
    };

    return (
        <>
            <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                <Form>
                    <h1>Login Form</h1>

                    <div>
                        <label htmlFor="username">Username: </label>
                        <Field type="text" id="username" name="username" autoComplete="off" />
                        <ErrorMessage name="username" component="div" />
                    </div>

                    <div>
                        <label htmlFor="password">Password: </label>
                        <Field type="password" id="password" name="password" autoComplete="off" />
                        <ErrorMessage name="password" component="div" />
                    </div>
                    
                    <br/>
                    <button type="submit">Login</button> | <Link to='/register'>Register</Link> | <Link to='/forgot-password'>Forgot Password</Link>
                </Form>
            </Formik>
        </>
    )
}

export default Login;