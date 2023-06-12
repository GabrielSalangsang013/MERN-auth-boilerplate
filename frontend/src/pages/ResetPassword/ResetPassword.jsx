import { useEffect, useState } from 'react';
import { useParams, useNavigate } from "react-router-dom";
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
import style from './ResetPassword.module.css';
import logo from '../../assets/logo-header.png';

const ResetPassword = () => {
    const navigate = useNavigate();
    const { token, csrfToken } = useParams();
    const [isAccountRecoveryResetPasswordTokenValid, setIsAccountRecoveryResetPasswordTokenValid] = useState(false);

    const initialValues = {
        password: '',
        repeatPassword: ''
    };

    const validationSchema = Yup.object().shape({
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
            .required('Please repeat your password')
    });

    const handleSubmit = (values) => {
        const {password, repeatPassword} = values;
        let sanitizedreset_passwordPassword = DOMPurify.sanitize(password);
        let sanitizedreset_passwordRepeatPassword = DOMPurify.sanitize(repeatPassword);

        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/reset-password`, {
            token: token,
            csrfToken: csrfToken,
            password: sanitizedreset_passwordPassword,
            repeatPassword: sanitizedreset_passwordRepeatPassword
        })
        .then((response) => {
           if(response.status === 200 && response.data.status === 'ok') {
                alert('Your have been successfully updated your password');
                navigate('/login');
           }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/forgot-password');
        });
    };

    useEffect(() => {
        if(token !== null) {
            axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/account-recovery/reset-password/verify-token`, {
                token: token,
                csrfToken: csrfToken
            })
            .then((response) => {
                if(response.status === 200 && response.data.status === 'ok') {
                    setIsAccountRecoveryResetPasswordTokenValid(true);
                }
            })
            .catch(function (error) {
                alert(error.response.data.message);
                navigate('/forgot-password');
            });
        }else {
            navigate('/');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);


    if(!isAccountRecoveryResetPasswordTokenValid) {
        return (
            <>
                <div className={`${style.container}`}>
                    <header className={`${style.header}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            
                        </div>
                    </header>
                    
                    <main className={`${style.main}`}>
                        <div className={`${style.reset_password_verify_token}`}>
                            <h1 className={`${style.reset_password_verify_token_title}`}>Loading...</h1>
                            <p className={`${style.reset_password_verify_token_subtitle}`}>Verifying may take a while. Please wait.</p>
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
                        <img className={`${style.logo}`} src={logo} alt="Logo" />
                    </div>
                    <div className={`${style.nav_links}`}>
                    </div>
                </header>
                
                
                <main className={`${style.main}`}>
                    <div className={`${style.reset_password_form}`}>
                        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                            <Form>
                                <h1 className={`${style.reset_password_form_title}`}>Reset Password</h1>
                                <p className={`${style.reset_password_form_subtitle}`}>Complete the form to reset your password</p>
                                <Field className={`${style.reset_password_form_input}`} placeholder='Enter your password' type="password" id="password" name="password"/>
                                <ErrorMessage name="password" component="div" className={`${style.reset_password_form_input_error}`}/>    

                                <Field className={`${style.reset_password_form_input}`} placeholder='Please repeat password' type="password" id="repeatPassword" name="repeatPassword"/>
                                <ErrorMessage name="repeatPassword" component="div" className={`${style.reset_password_form_input_error}`}/>    

                                <button className={`${style.reset_password_form_submit}`} type="submit">Submit</button>
                            </Form>
                        </Formik>
                    </div>
                </main>
            </div>
        </>
    )
}

export default ResetPassword;