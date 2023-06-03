require('dotenv').config();
const express = require('express');
const router = express.Router();
const jwt = require('jsonwebtoken');
const Tokens = require('csrf');

// ------------ CONTROLLERS --------------------
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
// ------------ CONTROLLERS --------------------

// ------------ CONSTANTS --------------------
const cookiesSettings = require('../constants/v1AuthenticationCookiesSettings');
// ------------ CONSTANTS --------------------

// ------------ MIDDLEWARES --------------------
const {
    userLimiter,
    loginLimiter,
    registerLimiter,
    activateLimiter,
    forgotPasswordLimiter,
    resetPasswordLimiter,
    resetPasswordVerifyTokenLimiter,
    logoutLimiter
} = require('../middlewares/v1AuthenticationLimiter');

function authenticateJWTToken(req, res, next) {
    const token = req.cookies.access_token;
    
    if (token == null) {
        // THE USER HAS NO JWT TOKEN
        return res.status(401).json({status: 'error', error: 'You are unauthorized user.'});
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            // THE USER HAS JWT TOKEN BUT INVALID 
            return res.status(403).json({status: 'error', error: 'You are forbidden. Invalid JWT Token.'});
        }

        // ADD CHECK IF HAS REQUIRED CLAIMS, OR MATCHES THE USER IN THE DATABASE

        req.user = user;
        next();
    })
}

function verifyPrivateCSRFToken(req, res, next) {
    const tokens = new Tokens();
    const csrfToken = req.cookies.csrf_token;
    
    if (csrfToken == null) {
        // THE USER HAS NO CSRF TOKEN
        return res.status(401).json({status: 'error', error: 'You are unauthorized user.'});
    }

    if (!tokens.verify(req.user.csrfTokenSecret.secret, csrfToken)) {
        // THE USER HAS CSRF TOKEN BUT INVALID 
        return res.status(403).json({status: 'error', error: 'You are forbidden. Invalid CSRF token.'});
    }

    next();
}

function verifyPublicCSRFToken(req, res, next) {
    const csrfToken = req.cookies.csrf_token;
    const tokens = new Tokens();

    if (csrfToken == null) {
        // THE USER HAS NO CSRF TOKEN
        return res.status(401).json({status: 'error', error: 'You are unauthorized user.'});
    }

    if (!tokens.verify(process.env.PUBLIC_CSRF_TOKEN_SECRET, csrfToken)) {
        // THE USER HAS CSRF TOKEN BUT INVALID 
        return res.status(403).json({status: 'error', error: 'You are forbidden. Invalid CSRF token.'});
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


// API THAT VERIFY PUBLIC CSRF TOKEN
router.post('/register', registerLimiter, verifyPublicCSRFToken, v1AuthenticationController.register);
router.post('/login', loginLimiter, verifyPublicCSRFToken, v1AuthenticationController.login);
router.post('/activate', activateLimiter, verifyPublicCSRFToken, v1AuthenticationController.activate);
router.post('/forgot-password', forgotPasswordLimiter, verifyPublicCSRFToken, v1AuthenticationController.forgotPassword);

// API THAT VERIFY PRIVATE CSRF TOKEN
router.get('/user', userLimiter, sendPublicCSRFTokenToUser, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/logout', logoutLimiter, sendPublicCSRFTokenToUser, authenticateJWTToken, verifyPrivateCSRFToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED

// API THAT VERIFY PRIVATE CSRF TOKEN VIA REQUEST BODY
router.post('/reset-password', resetPasswordLimiter, v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', resetPasswordVerifyTokenLimiter, v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);

module.exports = router