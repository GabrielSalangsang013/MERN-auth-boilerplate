import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import style from './AccountActivation.module.css';
import logo from '../../assets/logo-header.png';

const AccountActivation = () => {
    const navigate = useNavigate();
    const { token } = useParams();
    const [isActivated, setIsActivated] = useState(false);

    useEffect(() => {
        if(token !== null) {
            axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/activate`, {
                token: token
            })
            .then((response) => {
                if(response.status === 200 && response.data.status === 'ok') {
                    alert('You successfully activate your account');
                    setIsActivated(true);
                    navigate('/home');
                }
            })
            .catch(function (error) {
                alert(error.response.data.message);
                navigate('/register');
            });
        }else {
            navigate('/');
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    if(!isActivated) {
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
                        <div className={`${style.account_activation}`}>
                            <h1 className={`${style.account_activation_title}`}>Loading...</h1>
                            <p className={`${style.account_activation_subtitle}`}>Account activation may take a while. Please wait.</p>
                        </div>
                    </main>
                </div>
            </>
        )
    }
}

export default AccountActivation;