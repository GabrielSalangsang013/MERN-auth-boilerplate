import { useState } from 'react';
import { Link } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

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
        })
    };


    if(isUserAccountRecoveryResetPasswordEmailSent) {
        return (
            <>
                <h1>Email has been sent to recover your account by updating your password.</h1>
            </>
        )
    }

    return (
        <>
            <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                <Form>
                    <h1>Recovery Account Form</h1>

                    <div>
                        <label htmlFor="email">Email: </label>
                        <Field type="email" id="email" name="email" />
                        <ErrorMessage name="email" component="div" />
                    </div>

                    <br/>
                    <button type="submit">Submit</button> | <Link to='/login'>Login</Link> | <Link to='/register'>Register</Link>
                </Form>
            </Formik>
        </>
    )
}

export default ForgotPassword;