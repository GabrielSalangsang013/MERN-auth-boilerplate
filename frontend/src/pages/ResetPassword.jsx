import { useEffect, useState } from 'react';
import { useParams, useNavigate } from "react-router-dom";
import { Formik, Form, Field, ErrorMessage } from 'formik';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

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
        let sanitizedRegisterPassword = DOMPurify.sanitize(password);
        let sanitizedRegisterRepeatPassword = DOMPurify.sanitize(repeatPassword);

        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/reset-password`, {
            token: token,
            csrfToken: csrfToken,
            password: sanitizedRegisterPassword,
            repeatPassword: sanitizedRegisterRepeatPassword
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
        })
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
            })
        }else {
            navigate('/');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);


    if(!isAccountRecoveryResetPasswordTokenValid) {
        return (
            <>
                <h1>Loading...</h1>
            </>
        )
    }

    return (
        <>
            <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                <Form>
                    <h1>Recovery Account Reset Password Form</h1>
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

                    <br/>
                    <button type="submit">Submit</button>
                </Form>
            </Formik>
        </>
    )
}

export default ResetPassword;