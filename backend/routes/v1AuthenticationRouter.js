require('dotenv').config();
const express = require('express');
const router = express.Router();
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
const jwt = require('jsonwebtoken');
var Tokens = require('csrf');
const {
    userLimiter,
    loginLimiter,
    registerLimiter,
    activateLimiter,
    forgotPasswordLimiter,
    resetPasswordLimiter,
    resetPasswordVerifyTokenLimiter,
    logoutLimiter
} = require('../utils/v1AuthenticationLimiter');

const CSRF_TOKEN_EXPIRATION = 60 * 1000; // 60 secs - USED IN LOGIN AND ACTIVATE FUNCTION

function publicVerifyCSRFToken(req, res, next) {
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

function authenticateToken(req, res, next) {
    const token = req.cookies.access_token;
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
            expires: new Date(new Date().getTime() + CSRF_TOKEN_EXPIRATION)
        });
    }

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

// API THAT VERIFY PUBLIC CSRF TOKEN
router.post('/register', registerLimiter, publicVerifyCSRFToken, v1AuthenticationController.register);
router.post('/login', loginLimiter, publicVerifyCSRFToken, v1AuthenticationController.login);
router.post('/activate', activateLimiter, publicVerifyCSRFToken, v1AuthenticationController.activate);
router.post('/forgot-password', forgotPasswordLimiter, publicVerifyCSRFToken, v1AuthenticationController.forgotPassword);

// API THAT VERIFY PRIVATE CSRF TOKEN
router.get('/user', userLimiter, authenticateToken, verifyPrivateCSRFToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/logout', logoutLimiter, authenticateToken, verifyPrivateCSRFToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED

// API THAT VERIFY PRIVATE CSRF TOKEN VIA REQUEST BODY
router.post('/reset-password', resetPasswordLimiter, v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', resetPasswordVerifyTokenLimiter, v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);

module.exports = router