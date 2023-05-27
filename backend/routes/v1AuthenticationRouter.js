require('dotenv').config();
const express = require('express');
const router = express.Router();
const v1AuthenticationController = require('../controllers/v1AuthenticationController');
const jwt = require('jsonwebtoken');

function authenticateToken(req, res, next) {
    const token = req.cookies.access_token;
    if (token == null) {
        // THE USER HAS NO TOKEN
        console.log({
            fileName: 'v1AuthenticationRouter.js',
            errorDescription: 'Unauthorized',
            errorLocation: 'authenticateToken',
            statusCode: 401
        });
        return res.status(401).json({status: 'error', error: 'You are unauthorized user.'});
    }

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            // THE USER HAS TOKEN BUT INVALID 
            console.log({
                fileName: 'v1AuthenticationRouter.js',
                errorDescription: 'Forbidden or Invalid Token',
                errorLocation: 'authenticateToken',
                error: err,
                statusCode: 403
            });
            return res.status(403).json({status: 'error', error: 'You are forbidden.'});
        }
        req.user = user;
        next();
    })
}

router.get('/user', authenticateToken, v1AuthenticationController.user); // USER MUST BE AUTHETICATED
router.post('/register', v1AuthenticationController.register);
router.post('/login', v1AuthenticationController.login);
router.post('/logout', authenticateToken, v1AuthenticationController.logout); // USER MUST BE AUTHETICATED

module.exports = router