import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useDispatch } from 'react-redux';
import { successLoginAction, failLoginAction } from './actions/login';
import axios from 'axios'
axios.defaults.withCredentials = true

const Register = () => {
    const navigate = useNavigate()
    const dispatch = useDispatch()
    const [registerUsername, setRegisterUsername] = useState('')
    const [registerPassword, setRegisterPassword] = useState('')
    const [registerFullName, setRegisterFullName] = useState('')

    function handleRegister(e) {
        e.preventDefault()
        axios.post('http://localhost:4000/api/v1/authentication/register', {
            username: registerUsername,
            password: registerPassword,
            fullName: registerFullName
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
                // USER MUST COMPLETE THE REGISTRATION FORM
                alert(error.response.data.error)
            }else if(error.response.status === 500 && error.response.data.status === 'error') {
                // THIS IS AN ERROR FROM THE BACKEND
                alert(error.response.data.error)
            }

            dispatch(failLoginAction())
        })
    }

    return (
        <>
            <h1>Register</h1>
            <form>
                <input type='text' placeholder='Enter username' onChange={e => setRegisterUsername(e.target.value)}/>
                <input type='password' placeholder='Enter password' onChange={e => setRegisterPassword(e.target.value)}/>
                <input type='text' placeholder='Enter full name' onChange={e => setRegisterFullName(e.target.value)}/>
                <button type='submit' onClick={handleRegister}>Register</button>
            </form>
        </>
    )
}

export default Register;