require('dotenv').config();
const express = require('express');
const router = express.Router();
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
const jwt = require('jsonwebtoken');
const Tokens = require('csrf');
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

function authenticateToken(req, res, next) {
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

function verifyCSRFToken(req, res, next) {
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

router.get('/user', userLimiter, authenticateToken, verifyCSRFToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/register', registerLimiter, v1AuthenticationController.register);
router.post('/login', loginLimiter, v1AuthenticationController.login);
router.post('/activate', activateLimiter, v1AuthenticationController.activate);
router.post('/forgot-password', forgotPasswordLimiter, v1AuthenticationController.forgotPassword);
router.post('/reset-password', resetPasswordLimiter, v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', resetPasswordVerifyTokenLimiter, v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);
router.post('/logout', logoutLimiter, authenticateToken, verifyCSRFToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED

module.exports = router