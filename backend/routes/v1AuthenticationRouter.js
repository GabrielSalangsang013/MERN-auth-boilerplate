require('dotenv').config();
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Tokens = require('csrf');

// ------------ MODELS --------------------
const User = require("../models/userModel");
// ------------ MODELS --------------------

// ------------ CONTROLLERS --------------------
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
// ------------ CONTROLLERS --------------------

// ------------ CONSTANTS --------------------
const cookiesSettings = require('../constants/v1AuthenticationCookiesSettings'); // ALL COOKIES SETTINGS
const errorCodes = require('../constants/v1AuthenticationErrorCodes'); // ALL ERROR CODES
const userSettings = require('../constants/v1AuthenticationUserSettings'); // // DATA YOU DON'T WANT TO DELETE WHEN USER IS AUTHENTICATED
// ------------ CONSTANTS --------------------

// ------------ MIDDLEWARES --------------------
const {
    userLimiter,
    loginLimiter,
    verificationCodeLoginLimiter,
    verificationCodeLoginLogoutLimiter,
    registerLimiter,
    activateLimiter,
    forgotPasswordLimiter,
    deleteGoogleAuthenticatorQrCodeLimiter,
    resetPasswordLimiter,
    resetPasswordVerifyTokenLimiter,
    logoutLimiter,
    generateGoogleAuthenticationQRCodeLimiter,
    scannedGoogleAuthenticatorQrCodeLimiter
} = require('../middlewares/v1AuthenticationLimiter');

function checkIfHasMFALoginToken(req, res, next) {
    const mfa_login_token = req.cookies.mfa_login_token;
    
    if(mfa_login_token) {
        if(jwt.verify(mfa_login_token, process.env.MFA_LOGIN_TOKEN_SECRET)) {
            const {username, profilePicture, hasGoogleAuthentication} = jwt.decode(mfa_login_token); 
            return res.status(200).json({status: 'MFA-Mode', user: {username, profilePicture, hasGoogleAuthentication}}) 
        };
    }
    next();
}

function authenticateJWTToken(req, res, next) {
    const token = req.cookies.access_token;
    const csrfToken = req.cookies.csrf_token;
    
    if (token == null) {
        const tokens = new Tokens();
        // THE USER HAS NO JWT TOKEN
        if (!tokens.verify(process.env.PUBLIC_CSRF_TOKEN_SECRET, csrfToken)) {
            const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
            const csrfToken = tokens.create(csrfTokenSecret);
        
            res.cookie('csrf_token', csrfToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });
        }

        return res.status(401).json({message: 'You are unauthorized user.', errorCode: errorCodes.NO_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN});
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, async (error, user) => {
        if (error) {
            // THE USER HAS JWT TOKEN BUT INVALID
            res.cookie('access_token', 'expiredtoken', {
                httpOnly: true,
                secure: true,
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(0)
            });
        
            const tokens = new Tokens();
            const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
            const csrfToken = tokens.create(csrfTokenSecret);
        
            res.cookie('csrf_token', csrfToken, { 
                httpOnly: true, 
                secure: true, 
                sameSite: 'strict', 
                path: '/', 
                expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
            });

            return res.status(403).json({message: 'You are forbidden. Invalid JWT Token.', errorCode: errorCodes.INVALID_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN});
        }

        // CHECK IF HAS REQUIRED CLAIMS, OR MATCHES THE USER IN THE DATABASE
        const checkUser = await User.findById(user._id).populate('profile').populate('csrfTokenSecret').populate('googleAuthentication');

        if (!checkUser) {
            return res.status(404).json({message: "No user found inside JWT decoded.", errorCode: errorCodes.NO_USER_FOUND_IN_DATABASE_INSIDE_JWT_DECODED_TOKEN_AUTHENTICATE_JWT_TOKEN});
        }

        req.user = checkUser;
        next();
    });
}

function verifyPrivateCSRFToken(req, res, next) {
    const tokens = new Tokens();
    const csrfToken = req.cookies.csrf_token;
    
    if (csrfToken == null) {
        // THE USER HAS NO CSRF TOKEN
        res.cookie('access_token', 'expiredtoken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(0)
        });
    
        const tokens = new Tokens();
        const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
        const csrfToken = tokens.create(csrfTokenSecret);
    
        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        return res.status(401).json({message: 'You are unauthorized user.', errorCode: errorCodes.NO_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN});
    }

    if (!tokens.verify(req.user.csrfTokenSecret.secret, csrfToken)) {
        // THE USER HAS CSRF TOKEN BUT INVALID
        res.cookie('access_token', 'expiredtoken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(0)
        });
    
        const tokens = new Tokens();
        const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
        const csrfToken = tokens.create(csrfTokenSecret);
    
        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        
        return res.status(403).json({message: 'You are forbidden. Invalid CSRF token.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN});
    }

    userSettings.dataToRemoveRequestUser.forEach(eachDataToRemove => {
        req.user[eachDataToRemove] = undefined;
    });

    if(req.user.toObject().hasOwnProperty('googleAuthentication') && !req.user.googleAuthentication.isScanned) {
        req.user.googleAuthentication.secret = undefined;
        req.user.googleAuthentication.encoding = undefined;
        req.user.googleAuthentication.__v = undefined;
        req.user.googleAuthentication.user_id = undefined;
        req.user.googleAuthentication.otpauth_url = undefined;
        req.user.googleAuthentication.isScanned = undefined;
    }

    if(req.user.toObject().hasOwnProperty('googleAuthentication') && req.user.googleAuthentication.isScanned) {
        req.user.googleAuthentication.qr_code = undefined;
        req.user.googleAuthentication.secret = undefined;
        req.user.googleAuthentication.encoding = undefined;
        req.user.googleAuthentication.__v = undefined;
        req.user.googleAuthentication.user_id = undefined;
        req.user.googleAuthentication.otpauth_url = undefined;
    }
    
    next();
}

function verifyPublicCSRFToken(req, res, next) {
    const csrfToken = req.cookies.csrf_token;
    const tokens = new Tokens();

    if (csrfToken == null) {
        // THE USER HAS NO CSRF TOKEN
        const tokens = new Tokens();
        const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
        const csrfToken = tokens.create(csrfTokenSecret);
    
        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });

        return res.status(401).json({message: 'You are unauthorized user.', errorCode: errorCodes.NO_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN});
    }

    if (!tokens.verify(process.env.PUBLIC_CSRF_TOKEN_SECRET, csrfToken)) {
        // THE USER HAS CSRF TOKEN BUT INVALID 
        const tokens = new Tokens();
        const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
        const csrfToken = tokens.create(csrfTokenSecret);
    
        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
        
        return res.status(403).json({message: 'You are forbidden. Invalid CSRF token.', errorCode: errorCodes.INVALID_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN});
    }

    next();
}

function sendPublicCSRFTokenToUser(req, res, next) {
    // IF USER DON'T HAVE CSRF TOKEN, THE USER WILL RECEIVE PUBLIC CSRF TOKEN
    const csrfToken = req.cookies.csrf_token;

    if (csrfToken == null) {
        const tokens = new Tokens();
        const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
        const csrfToken = tokens.create(csrfTokenSecret);

        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
        });
    }

    next();
}
// ------------ MIDDLEWARES --------------------

// API THAT VERIFY PUBLIC CSRF TOKEN IN THE MIDDLEWARE
router.post('/register', registerLimiter, verifyPublicCSRFToken, v1AuthenticationController.register);
router.post('/login', loginLimiter, verifyPublicCSRFToken, v1AuthenticationController.login);
router.post('/activate', activateLimiter, verifyPublicCSRFToken, v1AuthenticationController.activate);
router.post('/forgot-password', forgotPasswordLimiter, verifyPublicCSRFToken, v1AuthenticationController.forgotPassword);

// API TWO/MULTI FACTOR AUTHENTICATION
router.post('/verification-code-login', verificationCodeLoginLimiter, verifyPublicCSRFToken, v1AuthenticationController.verificationCodeLogin);
router.post('/verification-code-login/logout', verificationCodeLoginLogoutLimiter, verifyPublicCSRFToken, v1AuthenticationController.verificationCodeLoginLogout);
router.post('/google-authentication-code-login', verificationCodeLoginLimiter, verifyPublicCSRFToken, v1AuthenticationController.googleAuthenticationCodeLogin);

// API SINGLE SIGN ON
router.post('/sso/google-identity-services', loginLimiter, verifyPublicCSRFToken, v1AuthenticationController.ssoGoogleIdentityServices);
router.post('/sso/firebase-facebook', loginLimiter, verifyPublicCSRFToken, v1AuthenticationController.ssoFirebaseFacebook);
router.post('/sso/firebase-google', loginLimiter, verifyPublicCSRFToken, v1AuthenticationController.ssoFirebaseGoogle);

// API THAT VERIFY PRIVATE CSRF TOKEN FIRST IN THE MIDDLEWARE
router.get('/user', userLimiter, checkIfHasMFALoginToken, sendPublicCSRFTokenToUser, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/logout', logoutLimiter, sendPublicCSRFTokenToUser, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED
router.post('/user/scanned-google-authentication-qr-code', scannedGoogleAuthenticatorQrCodeLimiter, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.scannedUserGoogleAuthenticatorQrCode)
router.post('/user/delete-google-authentication-qr-code', deleteGoogleAuthenticatorQrCodeLimiter, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.deleteUserGoogleAuthenticatorQrCode)
router.post('/user/generate-google-authentication-qr-code', generateGoogleAuthenticationQRCodeLimiter, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.generateGoogleAuthenticationQRCode);

// API THAT VERIFY PRIVATE CSRF TOKEN VIA REQUEST BODY INSIDE CONTROLLER
router.post('/reset-password', resetPasswordLimiter, v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', resetPasswordVerifyTokenLimiter, v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);

module.exports = router