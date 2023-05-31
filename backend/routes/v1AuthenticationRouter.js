require('dotenv').config();
const express = require('express');
const router = express.Router();
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
const jwt = require('jsonwebtoken');
const Tokens = require('csrf');

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

router.get('/user', authenticateToken, verifyCSRFToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/register', v1AuthenticationController.register);
router.post('/login', v1AuthenticationController.login);
router.post('/activate', v1AuthenticationController.activate);
router.post('/forgot-password', v1AuthenticationController.forgotPassword);
router.post('/reset-password', v1AuthenticationController.resetPassword);
router.post('/account-recovery/reset-password/verify-token', v1AuthenticationController.accountRecoveryResetPasswordVerifyToken);
router.post('/logout', authenticateToken, verifyCSRFToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED

module.exports = router