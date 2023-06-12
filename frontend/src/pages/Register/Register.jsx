import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './Register.module.css';
import logo from '../../assets/logo-header.png';

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
            .matches(/^[A-Za-z.\s]+$/, 'Full Name must contain letters and dots only')
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
        
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/register`, {
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
        });
    };

    if(isUserActivationEmailSent) { 
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
                            <Link to='/login' className={`${style.link}`}>Login</Link>
                        </div>
                    </header>
                    
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.activation_link_container}`}>
                            <h1 className={`${style.activation_link_container_title}`}>Activation Link Sent</h1>
                            <p className={`${style.activation_link_container_subtitle}`}>Your account activation link has been sent to your email</p>
                            <Link className={`${style.activation_link_login}`} to="/login">Go back to login page</Link>
                        </div>
                    </main>
                </div>
            </>
        )
    }

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
                        <Link to='/login' className={`${style.link}`}>Login</Link>
                    </div>
                </header>
                
                
                <main className={`${style.main}`}>
                    <div className={`${style.register_form}`}>
                    <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                        <Form>
                            <h1 className={`${style.register_form_title}`}>Create an account</h1>
                            <p className={`${style.register_form_subtitle}`}>Complete the form to create your account</p>

                            <Field className={`${style.register_form_input}`} placeholder='Enter your username' type="text" id="username" name="username"/>
                            <ErrorMessage name="username" component="div" className={`${style.register_form_input_error}`}/>

                            <Field className={`${style.register_form_input}`} placeholder='Enter your email' type="email" id="email" name="email"/>
                            <ErrorMessage name="email" component="div" className={`${style.register_form_input_error}`}/>    

                            <Field className={`${style.register_form_input}`} placeholder='Enter your password' type="password" id="password" name="password"/>
                            <ErrorMessage name="password" component="div" className={`${style.register_form_input_error}`}/>    

                            <Field className={`${style.register_form_input}`} placeholder='Please repeat password' type="password" id="repeatPassword" name="repeatPassword"/>
                            <ErrorMessage name="repeatPassword" component="div" className={`${style.register_form_input_error}`}/>    
                            
                            <Field className={`${style.register_form_input}`} placeholder='Enter your full name' type="fullName" id="fullName" name="fullName"/>
                            <ErrorMessage name="fullName" component="div" className={`${style.register_form_input_error}`}/>

                            <button className={`${style.register_form_submit}`} type="submit">Sign Up</button>
                        
                            <Link className={`${style.register_form_link_login}`} to="/login">Already have account?</Link>
                        </Form>
                    </Formik>
                    </div>
                </main>
            </div>
        </>
    )
}

export default Register;