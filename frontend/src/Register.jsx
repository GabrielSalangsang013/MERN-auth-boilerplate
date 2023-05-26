import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux';
import { successLoginAction } from './actions/login';
import { Formik, Form, Field, ErrorMessage } from 'formik';
import { escape } from 'he';
import * as Yup from 'yup';
import DOMPurify from 'dompurify';  // FOR SANITIZING USER INPUT TO PREVENT XSS ATTACKS BEFORE SENDING TO THE BACKEND
import axios from 'axios'
axios.defaults.withCredentials = true

const Register = () => {
    const navigate = useNavigate()
    const dispatch = useDispatch()

    const initialValues = {
        username: '',
        password: '',
        repeatPassword: '',
        fullName: '',
    };

    const validationSchema = Yup.object().shape({
        username: Yup.string()
            .required('Username is required')
            .min(4, 'Username must be at least 4 characters')
            .max(20, 'Username must not exceed 20 characters')
            .matches(/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores')
            .test(
                'username-security',
                'Username should not contain sensitive information',
                (value) => !/\b(admin|root|superuser)\b/i.test(value)
            )
            .test(
                'username-xss',
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
                /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/,
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
            .max(50, 'Full Name must not exceed 50 characters')
            .matches(/^[a-zA-Z\s]+$/, 'Full Name must contain letters only')
            .test(
              'full-name-xss',
              'Full Name contains potentially unsafe characters or invalid characters',
              (value) => {
                const sanitizedValue = escape(value);
                return sanitizedValue === value; // Check if sanitized value is the same as the original value
              }
            )
    });

    const handleSubmit = (values) => {
        // STEP 1: GET ALL THE INPUT VALUES THAT HAS BEEN SUCCESSFULLY PASSED TO VALIDATION
        const {username, password, repeatPassword, fullName} = values;

        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
        let sanitizedRegisterUsername = DOMPurify.sanitize(username);
        let sanitizedRegisterPassword = DOMPurify.sanitize(password);
        let sanitizedRegisterRepeatPassword = DOMPurify.sanitize(repeatPassword);
        let sanitizedRegisterFullName = DOMPurify.sanitize(fullName);
        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

        // STEP 3: SEND THE SANITIZED INPUT TO THE BACKEND FOR THE REGISTRATION OF THE ACCOUNT PURPOSES
        axios.post('http://localhost:4000/api/v1/authentication/register', {
            username: sanitizedRegisterUsername,
            password: sanitizedRegisterPassword,
            repeatPassword: sanitizedRegisterRepeatPassword,
            fullName: sanitizedRegisterFullName
        })
        .then((response) => {
           if(response.status === 200 && response.data.status === 'ok') {
                alert('Successfully registered')
                dispatch(successLoginAction());
                navigate('/');
           }
        })
        .catch(function (error) {
            if(error.response.status === 400 && error.response.data.status === 'fail') {
                // USER MUST COMPLETE THE REGISTER FORM FIELDS 
                // MUST PASSED IN THE VALIDATION IN THE BACKEND 
                // THE USERNAME MUST NOT EXIST OR MUST BE UNIQUE
                alert(error.response.data.error)
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error)
            }
        })
        // END SEND THE SANITIZED INPUT TO THE BACKEND FOR THE REGISTRATION OF THE ACCOUNT PURPOSES
    };

    return (
        <Formik initialValues={initialValues} validationSchema={validationSchema} onSubmit={handleSubmit}>
            <Form>
                <h1>Register Form</h1>
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
                <button type="submit">Submit</button>
            </Form>
        </Formik>
    )
}

export default Register;