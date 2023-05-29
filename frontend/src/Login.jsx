import { useEffect } from 'react';
import { useSelector, useDispatch } from 'react-redux';
import { successLoginAction } from './actions/login';
import { useNavigate } from 'react-router-dom';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios';
axios.defaults.withCredentials = true;

const Login = () => {
    const navigate = useNavigate();
    const dispatch = useDispatch();
    const isAuthenticated = useSelector((state) => state.isAuthenticated);

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
        // STEP 1: GET ALL THE INPUT VALUES THAT HAS BEEN SUCCESSFULLY PASSED TO VALIDATION
        const {username, password} = values;
        // END GET ALL THE INPUT VALUES THAT HAS BEEN SUCCESSFULLY PASSED TO VALIDATION
        
        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
        const sanitizedLoginUsername = DOMPurify.sanitize(username);
        const sanitizedLoginPassword = DOMPurify.sanitize(password);
        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

        // STEP 3: SEND THE SANITIZED INPUT TO THE BACKEND FOR THE LOGIN PURPOSES
        axios.post('http://localhost:4000/api/v1/authentication/login', {
            username: sanitizedLoginUsername,
            password: sanitizedLoginPassword
        })
        .then((response) => {
            if(response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged in.');
                dispatch(successLoginAction());
                navigate('/');
            } 
        })
        .catch(function (error) {
            if(error.response.status === 400 && error.response.data.status === 'fail') {
                // USER MUST COMPLETE THE LOGIN FORM FIELDS 
                // MUST PASSED IN THE VALIDATION IN THE BACKEND
                alert(error.response.data.error);
            }else if(error.response.status === 401 && error.response.data.status === 'fail') {
                // INVALID INPUT LOGIN FORM MEANS THAT USERNAME OR PASSWORD IS INCORRECT
                // THE USERNAME MUST EXIST
                // THE PASSWORD MUST BE MATCH THAT STORED IN THE BACKEND
                alert(error.response.data.error);
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error);
            }
        });
        // END SEND THE SANITIZED INPUT TO THE BACKEND FOR THE LOGIN PURPOSES
    }

    // IF USER IS ALREADY AUTHENTICATED. THE USER CANNOT NO LONGER VIEW THE LOGIN PAGE
    useEffect(() => {
        if(isAuthenticated) {
            window.location.replace('/');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, [])

    if(isAuthenticated) {
        return (
            <></>
        )
    }
    // END IF USER IS ALREADY AUTHENTICATED. THE USER CANNOT NO LONGER VIEW THE LOGIN PAGE

    return (
        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
            <Form>
                <h1>Login Form</h1>

                <div>
                    <label htmlFor="username">Username: </label>
                    <Field type="text" id="username" name="username" />
                    <ErrorMessage name="username" component="div" />
                </div>

                <div>
                    <label htmlFor="password">Password: </label>
                    <Field type="password" id="password" name="password" />
                    <ErrorMessage name="password" component="div" />
                </div>
                
                <br/>
                <button type="submit">Login</button>
            </Form>
        </Formik>
    )
}

export default Login;