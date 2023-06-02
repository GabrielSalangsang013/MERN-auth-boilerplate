import { useState } from 'react';
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
        // STEP 1: GET ALL THE INPUT VALUES THAT HAS BEEN SUCCESSFULLY PASSED TO VALIDATION
        const {email} = values;

        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
        let sanitizedRegisterEmail = DOMPurify.sanitize(email);
        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

        // STEP 3: SEND THE SANITIZED INPUT TO THE BACKEND FOR THE REGISTRATION OF THE ACCOUNT PURPOSES
        axios.post('http://localhost:4000/api/v1/authentication/forgot-password', {
            email: sanitizedRegisterEmail
        })
        .then((response) => {
           if(response.status === 200 && response.data.status === 'ok') {
                alert('Email has been sent to recover your account by updating your password.');
                setIsUserAccountRecoveryResetPasswordEmailSent(true);
           }
        })
        .catch(function (error) {
            if(error.response.status === 400 && error.response.data.status === 'fail') {
                // USER MUST COMPLETE THE RECOVERY ACCOUNT FORM FIELDS 
                // MUST PASSED IN THE VALIDATION IN THE BACKEND 
                // THE EMAIL IS NOT EXIST
                alert(error.response.data.error);
            }else if(error.response.status === 401 && error.response.data.status === 'error') {
                // THE USER HAS NO CSRF TOKEN
                alert(error.response.data.error);
            }else if(error.response.status === 403 && error.response.data.status === 'error') {
                // THE USER HAS CSRF TOKEN BUT INVALID 
                alert(error.response.data.error);
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // ERROR OCCURRED WHILE CHECKING THE EMAIL
                // ERROR OCCURRED WHILE UPDATING THE FORGOT PASSWORD OF THE USER
                // THIS IS AN ERROR FROM THE BACKEND
                // ERROR IN SENDING THE EMAIL ACCOUNT RECOVERY RESET PASSWORD
                alert(error.response.data.error);
            }
        })
        // END SEND THE SANITIZED INPUT TO THE BACKEND FOR THE REGISTRATION OF THE ACCOUNT PURPOSES
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
                    <button type="submit">Submit</button>
                </Form>
            </Formik>
        </>
    )
}

export default ForgotPassword;