import { useNavigate, useOutletContext  } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';

const LoginVerificationCode = () => {
    const navigate = useNavigate();
    const [user] = useOutletContext();

    const initialValues = {
        verificationCodeLogin: ''
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

    const handleSubmit = (values) => {
        const {verificationCodeLogin} = values;
        const sanitizedVerificationCodeLogin = DOMPurify.sanitize(verificationCodeLogin);
        axios.post(`${process.env.REACT_APP_API_KEY}/api/v1/authentication/verification-code-login`, {
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

    return (
        <>
            <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
                <Form>
                    <h1>Two Factor Authencation Login Code Form</h1>
                    <div>
                        <img src={user.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                    </div>
                    <br/>
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
}

export default LoginVerificationCode;