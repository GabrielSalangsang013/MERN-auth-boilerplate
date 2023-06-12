import { useEffect, useState, Fragment } from 'react';
import { useNavigate, useOutletContext } from 'react-router-dom';
import axios from 'axios';
import style from './Home.module.css';
import logo from '../../assets/logo-header.png';
import { Dialog, Transition } from '@headlessui/react'

const Home = () => {
    const navigate = useNavigate();
    const [userGoogleAuthenticatorQRCode, setUserGoogleAuthenticatorQRCode] = useState(undefined);
    const [displayButtonGenerateGoogleAuthenticationQRCode, setDisplayButtonGenerateGoogleAuthenticationQRCode] = useState(false);
    const [displayButtonDeleteGoogleAuthenticationQRCode, setDisplayButtonDeleteGoogleAuthenticationQRCode] = useState(false);
    const [isOpen, setIsOpen] = useState(false);
    const [toggle, setToggle] = useState(false)
    const [user] = useOutletContext();

    function closeModal() {
        setIsOpen(false)
    }

    function openModal() {
        setIsOpen(true)
    }

    function handleLogout(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/logout`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully logged out.');
                navigate('/login');
            }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    function handleSuccessfullyScannedQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/scanned-google-authentication-qr-code`)
        .then((response) => {
            if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Scanned Google Authenticator QR Code.');
                setUserGoogleAuthenticatorQRCode(undefined);
                setDisplayButtonDeleteGoogleAuthenticationQRCode(true);
            }
        })
        .catch(function (error) {
            alert(error.response.data.message);
            navigate('/login');
        });
    }

    function handleDeleteGoogleAuthenticationQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/delete-google-authentication-qr-code`)
        .then((response) => {
             if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Deleted Google Authenticator QR Code.');
                setDisplayButtonGenerateGoogleAuthenticationQRCode(true);
                setDisplayButtonDeleteGoogleAuthenticationQRCode(false);
             }
        })
        .catch(function (error) {
             alert(error.response.data.message);
             navigate('/login');
        });
    }

    function handleGenerateGoogleAuthenticationQRCode(e) {
        e.preventDefault();
        axios.post(`${process.env.REACT_APP_API}/api/v1/authentication/user/generate-google-authentication-qr-code`)
        .then((response) => {
             if (response.status === 200 && response.data.status === 'ok') {
                alert('Successfully Generated Google Authenticator QR Code.');
                setUserGoogleAuthenticatorQRCode(response.data.qr_code);
                setDisplayButtonGenerateGoogleAuthenticationQRCode(false);
             }
        })
        .catch(function (error) {
             alert(error.response.data.message);
             navigate('/login');
        });
    }

    useEffect(() => {
        if(!user.hasOwnProperty('googleAuthentication')) {
            setDisplayButtonGenerateGoogleAuthenticationQRCode(true);
        }

        if(user.hasOwnProperty('googleAuthentication') && !user.googleAuthentication.isScanned) {
            setUserGoogleAuthenticatorQRCode(user.googleAuthentication.qr_code);
        }

        if(user.hasOwnProperty('googleAuthentication') && user.googleAuthentication.isScanned) {
            setDisplayButtonDeleteGoogleAuthenticationQRCode(true);
        }
    // eslint-disable-next-line react-hooks/exhaustive-deps
    }, []);

    return (
        <>
            <div className={`${style.container}`}>
                <header className={`${style.header}`}>
                    <div className={`${style.flex_header_container}`}>
                        <div className={`${style.logo_container}`}>
                            <img className={`${style.logo}`} src={logo} alt="Logo" />
                        </div>
                        <div className={`${style.nav_links}`}>
                            <div className={`${style.header_drop_down_container}`}>
                                <button className={`${style.header_dropdown}`} onClick={() => setToggle(!toggle)} >
                                    <img className={`${style.profile_picture}`} src={user.profile.profilePicture} alt="nothing" width="25" /> &nbsp; {user.username}
                                    <svg className={`${style.header_dropdown_down_arrow}`} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20">
                                        <path fillRule="evenodd" d="M5.293 7.293a1 1 0 011.414 0L10 10.586l3.293-3.293a1 1 0 111.414 1.414l-4 4a1 1 0 01-1.414 0l-4-4a1 1 0 010-1.414z" clipRule="evenodd"></path>
                                    </svg>
                                </button>

                                {toggle && (
                                <div className={`${style.header_dropdown_menu}`}>
                                    <ul className={`${style.header_drodown_menu_list}`}>
                                        <li onClick={openModal} className={`${style.header_dropdown_menu_each_list}`}>Google Authentication</li>
                                        <li onClick={handleLogout} className={`${style.header_dropdown_menu_each_list}`}>Logout</li>
                                    </ul>
                                </div>
                                )}
                            </div>
                            {/* <Link to='/login' className={`${style.link}`}>Login</Link> */}
                        </div>
                    </div>
                </header>

                <main>
                    <div className={`${style.flex_main_container}`}>
                        <div className={`${style.box_message}`}>You're logged in!</div>

                        <Transition appear show={isOpen} as={Fragment}>
                            <Dialog as="div" className="relative z-10" onClose={closeModal}>
                            <Transition.Child as={Fragment}
                                enter="ease-out duration-300"
                                enterFrom="opacity-0"
                                enterTo="opacity-100"
                                leave="ease-in duration-200"
                                leaveFrom="opacity-100"
                                leaveTo="opacity-0"
                            >
                                <div className="fixed inset-0 bg-black bg-opacity-25" />
                            </Transition.Child>

                            <div className="fixed inset-0 overflow-y-auto">
                                <div className="flex min-h-full items-center justify-center p-4 text-center">
                                <Transition.Child as={Fragment}
                                    enter="ease-out duration-300"
                                    enterFrom="opacity-0 scale-95"
                                    enterTo="opacity-100 scale-100"
                                    leave="ease-in duration-200"
                                    leaveFrom="opacity-100 scale-100"
                                    leaveTo="opacity-0 scale-95"
                                >
                                    <Dialog.Panel className="w-full max-w-md transform overflow-hidden rounded-2xl bg-white p-6 text-left align-middle shadow-xl transition-all">
                                    <Dialog.Title
                                        as="h3"
                                        className="text-lg font-medium leading-6 text-gray-900"
                                    >
                                        MFA Google Authentication
                                    </Dialog.Title>
                                    <div className="mt-2">
                                        <p className="text-sm text-gray-500">
                                            You can add more security to your account by adding google authentication.
                                        </p>
                                    </div>

                                    <div className="mt-4">
                                        {
                                            displayButtonDeleteGoogleAuthenticationQRCode &&
                                            <button
                                                type="button"
                                                className="mt-2 mr-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                                onClick={handleDeleteGoogleAuthenticationQRCode}
                                                >
                                                Delete Google Authentication QR Code
                                            </button>
                                        }

                                        {
                                            displayButtonGenerateGoogleAuthenticationQRCode && 
                                            <button
                                                type="button"
                                                className="mt-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                                onClick={handleGenerateGoogleAuthenticationQRCode}
                                                >
                                                Generate Google Authentication QR Code
                                            </button>
                                        }

                                        {
                                            userGoogleAuthenticatorQRCode !== undefined && 
                                            <div>
                                                <div>
                                                    <img src={userGoogleAuthenticatorQRCode}  alt="User Google Authenticator QR Code"/>
                                                </div>
                                                <button
                                                    type="button"
                                                    className="mt-2 inline-flex justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                                    onClick={handleSuccessfullyScannedQRCode}
                                                    >
                                                    Successfully Scanned Google Authenticator QR Code
                                                </button>
                                            </div>
                                        }

                                        <button
                                            type="button"
                                            className="mt-2 justify-center rounded-md border border-transparent bg-blue-100 px-4 py-2 text-sm font-medium text-blue-900 hover:bg-blue-200 focus:outline-none focus-visible:ring-2 focus-visible:ring-blue-500 focus-visible:ring-offset-2"
                                            onClick={closeModal}
                                            >
                                            Go back
                                        </button>
                                        
                                    </div>
                                    </Dialog.Panel>
                                </Transition.Child>
                                </div>
                            </div>
                            </Dialog>
                        </Transition>
                    </div>
                </main>
            </div>
        </>
    )
}

export default Home;