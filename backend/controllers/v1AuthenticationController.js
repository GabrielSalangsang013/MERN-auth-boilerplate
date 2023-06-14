require('dotenv').config();
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const Tokens = require('csrf');
const Joi = require('joi');
const { escape } = require('he'); 
const xss = require('xss'); 
const mongoSanitize = require('express-mongo-sanitize');
const speakeasy = require('speakeasy');
const qrcode = require('qrcode');

// ----------------- MODELS -----------------
const User = require('../models/userModel');
const Profile = require('../models/profileModel');
const CSRFTokenSecret = require('../models/csrfTokenSecretModel');
const GoogleAuthentication = require('../models/googleAuthenticationModel');
// ----------------- MODELS -----------------

// ----------------- UTILITIES -----------------
const sendEmail = require('../utils/sendEmail'); // FOR SENDING EMAIL TO THE USER
const ErrorResponse = require('../utils/ErrorResponse'); // FOR SENDING ERROR TO THE ERROR HANDLER MIDDLEWARE
const { tryCatch } = require("../utils/tryCatch"); // FOR AVOIDING RETYPING TRY AND CATCH IN EACH CONTROLLER
const generateRandomPasswordSSO = require('../utils/generateRandomPasswordSSO');
const generateRandomUsernameSSO = require('../utils/generateRandomUsernameSSO');
// ----------------- UTILITIES -----------------

// ----------------- CONSTANTS -----------------
const emailTemplates = require('../constants/v1AuthenticationEmailTemplates'); // EMAIL TEMPLATES
const errorCodes = require('../constants/v1AuthenticationErrorCodes'); // ALL ERROR CODES
const cookiesSettings = require('../constants/v1AuthenticationCookiesSettings'); // ALL COOKIES SETTINGS
const jwtTokensSettings = require('../constants/v1AuthenticationJWTTokensSettings'); // ALL JWT TOKEN SETTINGS
const userSettings = require('../constants/v1AuthenticationUserSettings'); // // DATA YOU DON'T WANT TO DELETE WHEN USER IS AUTHENTICATED
// ----------------- CONSTANTS -----------------

const user = tryCatch(async (req, res) => {    
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

    return res.status(200).json({status: 'ok', user: req.user});
});

const register = tryCatch(async (req, res) => {
    let {username, email, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);
    if(!username || !email || !password || !repeatPassword || !fullName) throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM);

    username = xss(username);
    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);
    fullName = xss(fullName);

    const validationSchema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
        fullName: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({username, email, password, repeatPassword, fullName});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER);
    
    let user = await User.findOne({ username });
    if (user) throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER);

    user = await User.findOne({ email });
    if (user) throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER);

    const ACCOUNT_ACTIVATION_TOKEN = jwt.sign({username, email, password, repeatPassword, fullName}, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_ACTIVATION_EXPIRES_IN_STRING});
    const activateAccountURL = `${process.env.REACT_URL}/activate/${ACCOUNT_ACTIVATION_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_SUBJECT,
        text: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_TEXT,
        html: emailTemplates.ACCOUNT_ACTIVATION_EMAIL_HTML(activateAccountURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const activate = tryCatch(async (req, res) => {
    let { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "No Activate JWT Token", errorCodes.NO_ACCOUNT_ACTIVATION_JWT_TOKEN);

    jwt.verify(token, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, (error, jwtActivateTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid Activate JWT Token. Please sign up again.", errorCodes.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN);
        token = jwtActivateTokenDecoded;
    })

    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(token);
    if(!username || !email || !password || !repeatPassword || !fullName) throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM_ACTIVATE);

    username = xss(username);
    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);
    fullName = xss(fullName);

    const validationSchema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
        fullName: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({username, email, password, repeatPassword, fullName});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER_ACTIVATE);

    let user = await User.findOne({ username });
    if (user) throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER_ACTIVATE);

    user = await User.findOne({ email });
    if (user)  throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER_ACTIVATE);
    
    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: fullName, profilePicture: 'https://res.cloudinary.com/dgo6vnzjl/image/upload/c_fill,q_50,w_150/v1685085963/default_male_avatar_xkpekq.webp'});
    const savedUser = await User.create({
        username: username, 
        email: email, 
        password: password,
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id]
    });

    await CSRFTokenSecret.findByIdAndUpdate(savedCSRFTokenSecret._id, { user_id: savedUser._id });
    await Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id });
    
    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        savedUser[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(savedUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const login = tryCatch(async (req, res) => {
    let {username, password} = mongoSanitize.sanitize(req.body);
    if(!username || !password) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM);

    username = xss(username);
    password = xss(password);

    const validationSchema = Joi.object({
        username: Joi.string()
            .required()
            .trim()
            .min(4)
            .max(20)
            .pattern(/^[a-zA-Z0-9_]+$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('username-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('username-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Username must be a string',
                'string.empty': 'Username is required',
                'string.min': 'Username must be at least 4 characters',
                'string.max': 'Username must not exceed 20 characters',
                'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                'any.required': 'Username is required',
                'username-security': 'Username should not contain sensitive information',
                'username-xss-nosql': 'Invalid characters detected',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            })
    });

    const { error } = validationSchema.validate({username, password});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_LOGIN);

    const user = await User.findOne({ username }).populate('profile').populate('googleAuthentication');
    if (!user) throw new ErrorResponse(401, 'Invalid username.', errorCodes.USERNAME_NOT_EXIST_LOGIN);

    const isMatched = await user.matchPasswords(password);
    if (!isMatched) throw new ErrorResponse(401, 'Invalid password.', errorCodes.PASSWORD_NOT_MATCH_LOGIN);

    if (user.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_LOGIN);

    const sendVerificationCodeLogin = Array.from({ length: 7 }, () => (Math.random() < 0.33 ? String.fromCharCode(Math.floor(Math.random() * 26) + 65) : Math.random() < 0.67 ? String.fromCharCode(Math.floor(Math.random() * 26) + 97) : Math.floor(Math.random() * 10))).join('');
    const hashedSendVerificationCodeLogin = await argon2.hash(sendVerificationCodeLogin);

    await User.findOneAndUpdate({ username }, {verificationCodeLogin: hashedSendVerificationCodeLogin});

    await sendEmail({
        to: user.email,
        subject: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_SUBJECT,
        text: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_TEXT,
        html: emailTemplates.MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_HTML(sendVerificationCodeLogin)
    });

    let mfa_login_token;

    if(user.toObject().hasOwnProperty('googleAuthentication')) {
        if(user.googleAuthentication.isScanned) {
            mfa_login_token = jwt.sign({_id: user._id, username: user.username, profilePicture: user.profile.profilePicture, hasGoogleAuthentication: true }, process.env.MFA_LOGIN_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
        }else {
            mfa_login_token = jwt.sign({_id: user._id, username: user.username, profilePicture: user.profile.profilePicture, hasGoogleAuthentication: false }, process.env.MFA_LOGIN_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
        }
    }else {
        mfa_login_token = jwt.sign({_id: user._id, username: user.username, profilePicture: user.profile.profilePicture, hasGoogleAuthentication: false }, process.env.MFA_LOGIN_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING});
    }
    
    res.cookie('mfa_login_token', mfa_login_token, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_MFA_LOGIN_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const verificationCodeLogin = tryCatch(async (req, res) => {
    let {verificationCodeLogin} = mongoSanitize.sanitize(req.body);
    let mfa_login_token = req.cookies.mfa_login_token;

    if(!verificationCodeLogin || !mfa_login_token) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM_VERIFICATION_CODE_LOGIN);

    jwt.verify(mfa_login_token, process.env.MFA_LOGIN_TOKEN_SECRET, (error, jwtMFALoginTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired or Invalid Multi Factor Authentication Login Code Token. Please login again.", errorCodes.INVALID_OR_EXPIRED_MULTI_FACTOR_AUTHENTICATION_LOGIN_CODE);
        mfa_login_token = mongoSanitize.sanitize(jwtMFALoginTokenDecoded._id);
    });

    verificationCodeLogin = xss(verificationCodeLogin);
    mfa_login_token = xss(mfa_login_token);

    const validationSchema = Joi.object({
        verificationCodeLogin: Joi.string()
            .required()
            .length(7)
            .pattern(/^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/)
            .custom((value, helpers) => {
                if (/\b(admin|root|superuser)\b/i.test(value)) {
                    return helpers.error('verification-code-login-security');
                }
                return value;
            })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('verification-code-login-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Verification login code must be a string',
                'string.empty': 'Verification login code is required',
                'string.length': 'Verification login code must be {#limit} characters',
                'string.pattern.base': 'Verification login code must be 7 characters and contain only numbers and letters',
                'verification-code-login-security': 'Verification login code should not contain sensitive information',
                'verification-code-login-xss-nosql': 'Invalid characters detected',
            })
    });

    const { error } = validationSchema.validate({verificationCodeLogin});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_VERIFICATION_CODE_LOGIN);

    const user = await User.findById({ _id: mfa_login_token }).populate('csrfTokenSecret').populate('googleAuthentication');
    if (!user) throw new ErrorResponse(401, 'User not exist.', errorCodes.USER_NOT_EXIST_VERIFICATION_CODE_LOGIN);

    const isMatchedVerificationCodeLogin = await user.matchVerificationCodeLogin(verificationCodeLogin);
    if (!isMatchedVerificationCodeLogin) throw new ErrorResponse(401, 'Invalid verification code login.', errorCodes.VERIFICATION_CODE_LOGIN_NOT_MATCH);

    const tokens = new Tokens();
    const csrfTokenSecret = user.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        user[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('mfa_login_token', 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok', user: user});
});

const verificationCodeLoginLogout = tryCatch(async (req, res) => {
    res.cookie('csrf_token', 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
        expires: new Date(0)
    });
    
    res.cookie('mfa_login_token', 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        path: '/',
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok'});
});

const logout = tryCatch(async (req, res) => {
    const tokens = new Tokens();
    const csrfTokenSecret = process.env.PUBLIC_CSRF_TOKEN_SECRET;
    const csrfToken = tokens.create(csrfTokenSecret);

    res.cookie('access_token', 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(0)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_PUBLIC_CSRF_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const forgotPassword = tryCatch(async (req, res) => {
    let {email} = mongoSanitize.sanitize(req.body);
    if(!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM);

    email = xss(email);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            })
    });

    const { error } = validationSchema.validate({email});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD);

    let user = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!user) throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_FORGOT_PASSWORD);

    if (user.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_FORGOT_PASSWORD);

    await User.findOneAndUpdate({ email }, { forgotPassword: true });

    const tokens = new Tokens();
    const csrfTokenSecret = user.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    const ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN = jwt.sign({csrfToken}, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING});
    const ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN = jwt.sign({email}, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING});

    const recoverAccountResetPasswordURL = `${process.env.REACT_URL}/reset-password/${ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN}/${ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN}`;

    await sendEmail({
        to: email,
        subject: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT,
        text: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT,
        html: emailTemplates.RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML(recoverAccountResetPasswordURL),
    });

    return res.status(200).json({ status: 'ok' });
});

const googleAuthenticationCodeLogin = tryCatch(async (req, res) => {
    let {googleAuthenticationCodeLogin} = mongoSanitize.sanitize(req.body);
    let mfa_login_token = req.cookies.mfa_login_token;

    if(!verificationCodeLogin || !mfa_login_token) throw new ErrorResponse(400, "Please complete the Login form.", errorCodes.INCOMPLETE_LOGIN_FORM_GOOGLE_AUTHENTICATION_CODE_LOGIN);

    jwt.verify(mfa_login_token, process.env.MFA_LOGIN_TOKEN_SECRET, (error, jwtMFALoginTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired or Invalid Multi Factor Authentication Login Code Token. Please login again.", errorCodes.INVALID_OR_EXPIRED_MULTI_FACTOR_AUTHENTICATION_LOGIN_CODE_GOOGLE_AUTHENTICATION_CODE_LOGIN);
        mfa_login_token = mongoSanitize.sanitize(jwtMFALoginTokenDecoded._id);
    });

    googleAuthenticationCodeLogin = xss(googleAuthenticationCodeLogin);
    mfa_login_token = xss(mfa_login_token);

    console.log(googleAuthenticationCodeLogin);

    const validationSchema = Joi.object({
        googleAuthenticationCodeLogin: Joi.string()
            .required()
            .pattern(/^\d{6}$/)
            .messages({
                'string.base': 'Google Authentication Code Login must be a string',
                'string.empty': 'Google Authentication Code Login is required',
                'string.pattern.base': 'Code must be a 6-digit number',
                'any.required': 'Google Authentication Code Login is required',
            }),
    });

    const { error } = validationSchema.validate({googleAuthenticationCodeLogin});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_GOOGLE_AUTHENTICATION_CODE_LOGIN);

    const user = await User.findById({ _id: mfa_login_token }).populate('csrfTokenSecret').populate('googleAuthentication');
    if (!user) throw new ErrorResponse(401, 'User not exist.', errorCodes.USER_NOT_EXIST_VERIFICATION_CODE_LOGIN);

    const isVerified = speakeasy.totp.verify({
        secret: user.googleAuthentication.secret,
        encoding: user.googleAuthentication.encoding,
        token: googleAuthenticationCodeLogin
    });

    if(!isVerified) throw new ErrorResponse(401, 'Invalid Google Authentication Code Login', errorCodes.INVALID_GOOGLE_AUTHENTICATION_CODE_LOGIN);

    const tokens = new Tokens();
    const csrfTokenSecret = user.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        user[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('mfa_login_token', 'expiredtoken', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(0)
    });

    return res.status(200).json({status: 'ok', user: user});
});

const generateGoogleAuthenticationQRCode = tryCatch(async (req, res) => {
    const googleAuthenticationSecret = speakeasy.generateSecret({name: process.env.GOOGLE_AUTHENTICATOR_NAME});
    const googleAuthenticatorQRCode = await qrcode.toDataURL(googleAuthenticationSecret.otpauth_url);
    const savedGoogleAuthentication = await GoogleAuthentication.create({
        secret: googleAuthenticationSecret.ascii, 
        encoding: 'ascii', 
        qr_code: googleAuthenticatorQRCode,
        otpauth_url: googleAuthenticationSecret.otpauth_url,
        isScanned: false
    });

    await User.findByIdAndUpdate(req.user._id, { googleAuthentication: [savedGoogleAuthentication._id] });
    await GoogleAuthentication.findByIdAndUpdate(savedGoogleAuthentication._id, { user_id: req.user._id });

    res.status(200).json({status: 'ok', qr_code: googleAuthenticatorQRCode});
});

const scannedUserGoogleAuthenticatorQrCode = tryCatch(async (req, res) => {
    await GoogleAuthentication.findOneAndUpdate({ user_id: req.user._id }, { isScanned: true });
    res.status(200).json({ status: 'ok' });
});

const deleteUserGoogleAuthenticatorQrCode = tryCatch(async (req, res) => {
    await GoogleAuthentication.findOneAndDelete({ user_id: req.user._id });
    await User.updateOne({ _id: req.user._id }, { $unset: { googleAuthentication: req.user.googleAuthentication._id } })
    res.status(200).json({ status: 'ok' });
});

const resetPassword = tryCatch(async (req, res) => {
    let { token, csrfToken, password, repeatPassword } = mongoSanitize.sanitize(req.body);

    if(!token || !csrfToken) throw new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD);
    
    jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, (error, jwtCSRFTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD);
        csrfToken = jwtCSRFTokenDecoded;
    });

    jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, (error, jwtRecoveryAccountTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD);
        token = jwtRecoveryAccountTokenDecoded;
    });
    
    let { email } = mongoSanitize.sanitize(token);
    let csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if(!email || !password || !repeatPassword) throw new ErrorResponse(400, "Please complete the Recovery Account Reset Password Form.", errorCodes.INCOMPLETE_RESET_PASSWORD_FORM);
    if(password !== repeatPassword) throw new ErrorResponse(400, "Password and Repeat Password is not match", errorCodes.PASSWORD_REPEAT_PASSWORD_NOT_MATCH_RESET_PASSWORD_FORM);

    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        password: Joi.string()
            .required()
            .min(12)
            .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/)
            .custom((value, helpers) => {
                if (/\b(password|123456789)\b/i.test(value)) {
                    return helpers.error('password-security');
                }
                return value;
            })
            .messages({
                'string.base': 'Password must be a string',
                'string.empty': 'Password is required',
                'string.min': 'Password must be at least 12 characters',
                'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                'any.required': 'Password is required',
                'password-security': 'Password should not be commonly used or easily guessable',
            }),
        repeatPassword: Joi.string()
            .required()
            .valid(Joi.ref('password'))
            .messages({
                'string.base': 'Repeat Password must be a string',
                'string.empty': 'Please repeat your password',
                'any.only': 'Passwords must match',
                'any.required': 'Please repeat your password',
            }),
    });

    const { error } = validationSchema.validate({email, password, repeatPassword});

    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_RESET_PASSWORD);
    
    let user = await User.findOne({ email }).populate('csrfTokenSecret');
    if (!user) throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_RESET_PASSWORD);

    if (user.isSSO) throw new ErrorResponse(401, 'The user is SSO account.', errorCodes.USER_SSO_ACCOUNT_RESET_PASSWORD);

    const tokens = new Tokens();
    if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) throw new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_RESET_PASSWORD);
    
    const hashedPassword = await argon2.hash(password);
    user = await User.findOneAndUpdate({ email }, { password: hashedPassword, forgotPassword: false });

    return res.status(200).json({ status: 'ok'});
});

const accountRecoveryResetPasswordVerifyToken = tryCatch(async (req, res) => {
    let { token, csrfToken } = mongoSanitize.sanitize(req.body);
    if(!token || !csrfToken) throw new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
   
    jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, (error, jwtCSRFTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        csrfToken = jwtCSRFTokenDecoded;
    });

    jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, (error, jwtRecoveryAccountTokenDecoded) => {
        if(error) throw new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
        token = jwtRecoveryAccountTokenDecoded;
    });

    let { email } = mongoSanitize.sanitize(token);
    let csrfTokenObj = mongoSanitize.sanitize(csrfToken);

    if(!email) throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    email = xss(email);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            })
    });

    const { error } = validationSchema.validate({email});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    let user = await User.findOne({ email, forgotPassword: true }).populate('csrfTokenSecret');
    if (!user) throw new ErrorResponse(400, "Email is not exist or user does not request forgot password.", errorCodes.EMAIL_NOT_EXIST_OR_USER_NOT_REQUEST_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    const tokens = new Tokens();
    if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) throw new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);

    return res.status(200).json({ status: 'ok' });
});

const ssoGoogleIdentityServices = tryCatch(async (req, res) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "No SSO JWT Token", errorCodes.NO_SSO_JWT_TOKEN_SSO_GOOGLE_IDENTITY_SERVICES);

    let { email, name, picture } = mongoSanitize.sanitize(jwt.decode(token));
    if(!email || !name || !picture) throw new ErrorResponse(400, "Credential must have email, name, and picture.", errorCodes.INCOMPLETE_CREDENTIAL_SSO_GOOGLE_IDENTITY_SERVICES);

    email = xss(email);
    name = xss(name);
    picture = xss(picture);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({email, name});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_GOOGLE_IDENTITY_SERVICES);

    const user = await User.findOne({ email }).populate('csrfTokenSecret');
    
    // IF USER EXIST BY EMAIL JUST LOGIN 
    if (user) {
        const tokens = new Tokens();
        const csrfTokenSecret = user.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
            user[eachDataToRemove] = undefined;
        });

        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
        
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok', user: user});
    }

    // IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: picture});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true
    });

    await CSRFTokenSecret.findByIdAndUpdate(savedCSRFTokenSecret._id, { user_id: savedUser._id });
    await Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id });
    
    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        savedUser[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(savedUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const ssoFirebaseFacebook = tryCatch(async (req, res) => {
    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "No SSO JWT Token", errorCodes.NO_SSO_JWT_TOKEN_SSO_FIREBASE_FACEBOOK);

    let { email, name, picture } = mongoSanitize.sanitize(jwt.decode(token));
    if(!email || !name || !picture) throw new ErrorResponse(400, "Credential must have email, name, and picture", errorCodes.INCOMPLETE_CREDENTIAL_SSO_FIREBASE_FACEBOOK);
    
    email = xss(email);
    name = xss(name);
    picture = xss(picture);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({email, name});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_FIREBASE_FACEBOOK);

    const user = await User.findOne({ email }).populate('csrfTokenSecret');
    
    // IF USER EXIST BY EMAIL JUST LOGIN 
    if (user) {
        const tokens = new Tokens();
        const csrfTokenSecret = user.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
            user[eachDataToRemove] = undefined;
        });

        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
        
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok', user: user});
    }

    // IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: picture});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true
    });

    await CSRFTokenSecret.findByIdAndUpdate(savedCSRFTokenSecret._id, { user_id: savedUser._id });
    await Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id });
    
    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        savedUser[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(savedUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

const ssoFirebaseGoogle = tryCatch(async (req, res) => {
    // NOTE FIBASE GOOGLE ACCESS TOKEN HAS EMAIL VERIFIED FIELD 
    // WHICH SSO GOOGLE IDENTITY SERVICES DON'T HAVE THAT.
    // SO IF YOU THINK WHY IT HAS email_verified IN THIS CONTROLLER BECAUSE ONLY FIREBASE HAVE THAT.

    const { token } = mongoSanitize.sanitize(req.body);
    if(!token) throw new ErrorResponse(401, "No SSO JWT Token", errorCodes.NO_SSO_JWT_TOKEN_SSO_FIREBASE_GOOGLE);

    let { email, name, picture, email_verified } = mongoSanitize.sanitize(jwt.decode(token));
    if(!email || !name || !picture || !email_verified) throw new ErrorResponse(400, "Credential must have email, name, picture, and email verified", errorCodes.INCOMPLETE_CREDENTIAL_SSO_FIREBASE_GOOGLE);
    if(!email_verified) throw new ErrorResponse(400, "Email is not verified", errorCodes.EMAIL_NOT_VERIFIED_SSO_FIREBASE_GOOGLE);

    email = xss(email);
    name = xss(name);
    picture = xss(picture);

    const validationSchema = Joi.object({
        email: Joi.string()
            .required()
            .trim()
            .pattern(/^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/)
            .email({ minDomainSegments: 2, tlds: { allow: false } })
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('email-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Email must be a string',
                'string.empty': 'Email is required',
                'string.pattern.base': 'Please enter a valid email address',
                'string.email': 'Please enter a valid email address',
                'any.required': 'Email is required',
                'email-xss-nosql': 'Invalid email format or potentially unsafe characters',
            }),
        name: Joi.string()
            .required()
            .trim()
            .max(50)
            .regex(/^[A-Za-z.\s]+$/)
            .custom((value, helpers) => {
                const sanitizedValue = escape(value);
                if (sanitizedValue !== value) {
                    return helpers.error('full-name-xss-nosql');
                }
                return value;
            })
            .messages({
                'string.base': 'Full Name must be a string',
                'string.empty': 'Full Name is required',
                'string.max': 'Full Name must not exceed 50 characters',
                'string.pattern.base': 'Full Name must contain letters and dots only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({email, name});
    if (error) throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_CREDENTIAL_SSO_FIREBASE_GOOGLE);

    const user = await User.findOne({ email }).populate('csrfTokenSecret');
    
    // IF USER EXIST BY EMAIL JUST LOGIN 
    if (user) {
        const tokens = new Tokens();
        const csrfTokenSecret = user.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);

        userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
            user[eachDataToRemove] = undefined;
        });

        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
        
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        res.cookie('csrf_token', csrfToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok', user: user});
    }

    // IF USER NOT EXIST. REGISTER THE USER AFTER THAT AUTOMATICALLY LOGIN THE USER
    const tokens = new Tokens();
    const csrfTokenSecret = tokens.secretSync();
    const csrfToken = tokens.create(csrfTokenSecret);

    const savedCSRFTokenSecret = await CSRFTokenSecret.create({secret: csrfTokenSecret});
    const savedProfile = await Profile.create({fullName: name, profilePicture: picture});
    const savedUser = await User.create({
        username: name.split(" ")[0] + "_" + generateRandomUsernameSSO(), 
        email: email, 
        password: generateRandomPasswordSSO(),
        profile: [savedProfile._id],
        csrfTokenSecret: [savedCSRFTokenSecret._id],
        isSSO: true
    });

    await CSRFTokenSecret.findByIdAndUpdate(savedCSRFTokenSecret._id, { user_id: savedUser._id });
    await Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id });
    
    userSettings.dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
        savedUser[eachDataToRemove] = undefined;
    });

    let accessToken = jwt.sign(savedUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
    
    res.cookie('access_token', accessToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    res.cookie('csrf_token', csrfToken, { 
        httpOnly: true, 
        secure: true, 
        sameSite: 'strict', 
        path: '/', 
        expires: new Date(new Date().getTime() + cookiesSettings.COOKIE_ACCESS_TOKEN_EXPIRATION)
    });

    return res.status(200).json({status: 'ok'});
});

module.exports = {
    user,
    register,
    activate,
    login,
    verificationCodeLogin,
    verificationCodeLoginLogout,
    googleAuthenticationCodeLogin,
    generateGoogleAuthenticationQRCode,
    logout,
    forgotPassword,
    scannedUserGoogleAuthenticatorQrCode,
    deleteUserGoogleAuthenticatorQrCode,
    resetPassword,
    accountRecoveryResetPasswordVerifyToken,
    ssoGoogleIdentityServices,
    ssoFirebaseFacebook,
    ssoFirebaseGoogle
};