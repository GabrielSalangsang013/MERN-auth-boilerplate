import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './ForgotPassword.module.css';
import logo from '../../assets/logo-header.png';

const ForgotPassword = () => {
    const [isUserAccountRecoveryResetPasswordEmailSent, setIsUserAccountRecoveryResetPasswordEmailSent] = useState(false);

    const initialValues = {
        email: ''
    };

    const validationSchema = Yup.object().shape({
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
            )
    });

    const handleSubmit = (values) => {
        const {email} = values;
        let sanitizedRegisterEmail = DOMPurify.sanitize(email);
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/forgot-password`, {
            email: sanitizedRegisterEmail
        })
        .then((response) => {
           if(response.status === 200 && response.data.status === 'ok') {
                alert('Email has been sent to recover your account by updating your password.');
                setIsUserAccountRecoveryResetPasswordEmailSent(true);
           }
        })
        .catch(function (error) {
            alert(error.response.data.message);
        });
    };


    if(isUserAccountRecoveryResetPasswordEmailSent) {
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
                            <Link to='/register' className={`${style.link}`}>Register</Link>
                        </div>
                    </header>
                    
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.recovery_account_link}`}>
                            <h1 className={`${style.recovery_account_link_title}`}>Recovery Account Email Sent</h1>
                            <p className={`${style.recovery_account_link_subtitle}`}>Email has been sent to recover your account by updating your password.</p>
                            <Link className={`${style.recovery_account_link_login}`} to="/login">Go back to login page</Link>
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
                        <Link to='/register' className={`${style.link}`}>Register</Link>
                    </div>
                </header>
                
                
                <main className={`${style.main}`}>
                    <div className={`${style.forgot_password_form}`}>
                    <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                        <Form>
                            <h1 className={`${style.forgot_password_form_title}`}>Recovery Account Form</h1>
                            <p className={`${style.forgot_password_form_subtitle}`}>You forgot your password? Don't worry enter your email here to reset your passwrd.</p>

                            <Field className={`${style.forgot_password_form_input}`} placeholder='Enter your email' type="email" id="email" name="email"/>
                            <ErrorMessage name="email" component="div" className={`${style.forgot_password_form_input_error}`}/>
                            
                            <button className={`${style.forgot_password_form_submit}`} type="submit">Submit</button>
                        </Form>
                    </Formik>
                    </div>
                </main>
            </div>
        </>
    )
}

export default ForgotPassword;