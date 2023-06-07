import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const Register = () => {
    const [isUserActivationEmailSent, setIsUserActivationEmailSent] = useState(false);

    const initialValues = {
        username: '',
        email: '',
        password: '',
        repeatPassword: '',
        fullName: '',
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
        email: Yup.string()
            .required('Email is required')
            .trim()
            .matches(
                /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
                'Please enter a valid email address'
            )
            .email('Please enter a valid email address')
            .test(
              'email-xss-nosql',
              'Invalid email format or potentially unsafe characters',
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
            ),
        repeatPassword: Yup.string()
            .oneOf([Yup.ref('password'), null], 'Passwords must match')
            .required('Please repeat your password'),
        fullName: Yup.string()
            .required('Full Name is required')
            .trim()
            .max(50, 'Full Name must not exceed 50 characters')
            .matches(/^[a-zA-Z\s]+$/, 'Full Name must contain letters only')
            .test(
              'full-name-xss-nosql',
              'Full Name contains potentially unsafe characters or invalid characters',
              (value) => {
                const sanitizedValue = escape(value);
                return sanitizedValue === value; // Check if sanitized value is the same as the original value
              }
            )
    });

    const handleSubmit = (values) => {
        const {username, email, password, repeatPassword, fullName} = values;
        let sanitizedRegisterUsername = DOMPurify.sanitize(username);
        let sanitizedRegisterEmail = DOMPurify.sanitize(email);
        let sanitizedRegisterPassword = DOMPurify.sanitize(password);
        let sanitizedRegisterRepeatPassword = DOMPurify.sanitize(repeatPassword);
        let sanitizedRegisterFullName = DOMPurify.sanitize(fullName);
        
        axios.post(`${process.env.REACT_APP_API_KEY}/api/v1/authentication/register`, {
            username: sanitizedRegisterUsername,
            email: sanitizedRegisterEmail,
            password: sanitizedRegisterPassword,
            repeatPassword: sanitizedRegisterRepeatPassword,
            fullName: sanitizedRegisterFullName
        })
        .then((response) => {
           if(response.status === 200 && response.data.status === 'ok') {
                alert('Email has been sent to activate your account');
                setIsUserActivationEmailSent(true);
           }
        })
        .catch(function (error) {
            alert(error.response.data.message);
        })
    };

    if(isUserActivationEmailSent) { 
        return (
            <>
                <h1>Your account activation link has been sent to your email.</h1>
            </>
        )
    }

    return (
        <>
            <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                <Form>
                    <h1>Register Form</h1>
                    <div>
                        <label htmlFor="username">Username: </label>
                        <Field type="text" id="username" name="username" />
                        <ErrorMessage name="username" component="div" />
                    </div>

                    <div>
                        <label htmlFor="email">Email: </label>
                        <Field type="email" id="email" name="email" />
                        <ErrorMessage name="email" component="div" />
                    </div>

                    <div>
                        <label htmlFor="password">Password: </label>
                        <Field type="password" id="password" name="password" />
                        <ErrorMessage name="password" component="div" />
                    </div>

                    <div>
                        <label htmlFor="repeatPassword">Repeat Password: </label>
                        <Field type="password" id="repeatPassword" name="repeatPassword" />
                        <ErrorMessage name="repeatPassword" component="div" />
                    </div>

                    <div>
                        <label htmlFor="fullName">Full Name: </label>
                        <Field type="text" id="fullName" name="fullName" />
                        <ErrorMessage name="fullName" component="div" />
                    </div>
                    
                    <br/>
                    <button type="submit">Submit</button> | <Link to='/login'>Login</Link>
                </Form>
            </Formik>
        </>
    )
}

export default Register;