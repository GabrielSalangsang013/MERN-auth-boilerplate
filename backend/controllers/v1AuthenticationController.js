require('dotenv').config();
const jwt = require('jsonwebtoken');
const argon2 = require('argon2');
const Tokens = require('csrf');
const Joi = require('joi');
const { escape } = require('he'); 
const xss = require('xss'); 
const mongoSanitize = require('express-mongo-sanitize');

// ----------------- MODELS -----------------
const User = require('../models/userModel');
const Profile = require('../models/profileModel');
const CSRFTokenSecret = require('../models/csrfTokenSecretModel');
// ----------------- MODELS -----------------

// ----------------- UTILITIES -----------------
const sendEmail = require('../utils/sendEmail'); // FOR SENDING EMAIL TO THE USER
const ErrorResponse = require('../utils/ErrorResponse'); // FOR SENDING ERROR TO THE ERROR HANDLER MIDDLEWARE
const { tryCatch } = require("../utils/tryCatch"); // FOR AVOIDING RETYPING TRY AND CATCH IN EACH CONTROLLER
// ----------------- UTILITIES -----------------

// ----------------- CONSTANTS -----------------
const emailTemplates = require('../constants/v1AuthenticationEmailTemplates'); // EMAIL TEMPLATES
const errorCodes = require('../constants/v1AuthenticationErrorCodes'); // ALL ERROR CODES
const cookiesSettings = require('../constants/v1AuthenticationCookiesSettings'); // ALL COOKIES SETTINGS
const jwtTokensSettings = require('../constants/v1AuthenticationJWTTokensSettings'); // ALL JWT TOKEN SETTINGS
const {dataToRemoveInsideUserJWTToken} = require('../constants/v1AuthenticationUserSettings'); // // DATA YOU DON'T WANT TO DELETE WHEN USER IS AUTHENTICATED
// ----------------- CONSTANTS -----------------

const user = tryCatch(async (req, res) => {    
    return res.status(200).json({status: 'ok', user: req.user});
});

const register = tryCatch(async (req, res) => {
    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
    let {username, email, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);

    if(!username || !email || !password || !repeatPassword || !fullName) {
        throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM);
    }
    // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

    // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
    username = xss(username);
    email = xss(email);
    password = xss(password);
    repeatPassword = xss(repeatPassword);
    fullName = xss(fullName);
    // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

    // STEP 3: VALIDATE USER INPUT
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
            .regex(/^[a-zA-Z\s]+$/)
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
                'string.pattern.base': 'Full Name must contain letters only',
                'any.required': 'Full Name is required',
                'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
            })
    });

    const { error } = validationSchema.validate({username, email, password, repeatPassword, fullName});

    if (error) {
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER);
    }
    // END VALIDATE USER INPUT

    // STEP 4: CHECK IF USERNAME IS EXIST
    let user = await User.findOne({ username });

    if (user) {
        throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER);
    }
    // END CHECK IF USERNAME IS EXIST

    // STEP 5: CHECK IF EMAIL IS EXIST
    user = await User.findOne({ email });

    if (user) {
        throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER);
    }
    // END CHECK IF EMAIL IS EXIST

    // STEP 6: SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT
    const ACCOUNT_ACTIVATION_TOKEN = jwt.sign({username, email, password, repeatPassword, fullName}, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCOUNT_ACTIVATION_EXPIRES_IN_STRING});
    const activateAccountURL = `${process.env.REACT_URL}/activate/${ACCOUNT_ACTIVATION_TOKEN}`;
    const html = emailTemplates.accountActivationEmailTemplate(activateAccountURL);

    await sendEmail({
        to: email,
        subject: "MERN with Auth - Account Activation",
        text: "Your account will be activated by clicking the link below",
        html,
    });

    return res.status(200).json({ status: 'ok' });
    // END SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT
});

const activate = tryCatch(async (req, res) => {
    const { token } = req.body;

    if(!token){
        throw new ErrorResponse(401, "No Activate JWT Token", errorCodes.NO_ACCOUNT_ACTIVATION_JWT_TOKEN);
    }else {
        jwt.verify(token, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, async (error, jwtTokenDecoded) => {
            if(error) {
                throw new ErrorResponse(401, "Expired link or Invalid Activate JWT Token. Please sign up again.", errorCodes.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN);
            }else {
                // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(jwtTokenDecoded);

                if(!username || !email || !password || !repeatPassword || !fullName) {
                    throw new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM_ACTIVATE);
                }
                // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

                // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
                username = xss(username);
                email = xss(email);
                password = xss(password);
                repeatPassword = xss(repeatPassword);
                fullName = xss(fullName);
                // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

                // STEP 3: VALIDATE USER INPUT
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
                        .regex(/^[a-zA-Z\s]+$/)
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
                            'string.pattern.base': 'Full Name must contain letters only',
                            'any.required': 'Full Name is required',
                            'full-name-xss-nosql': 'Full Name contains potentially unsafe characters or invalid characters',
                        })
                });

                const { error } = validationSchema.validate({username, email, password, repeatPassword, fullName});

                if (error) {
                    throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER_ACTIVATE);
                }
                // END VALIDATE USER INPUT

                // STEP 4: CHECK IF USERNAME IS EXIST
                let user = await User.findOne({ username });

                if (user) {
                    throw new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER_ACTIVATE);
                }
                // END CHECK IF USERNAME IS EXIST

                // STEP 5: CHECK IF EMAIL IS EXIST
                user = await User.findOne({ email });

                if (user) {
                    throw new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER_ACTIVATE);
                }
                // END CHECK IF EMAIL IS EXIST

                // STEP 6: CREATE CSRF TOKEN SECRET, CSRF TOKEN, PROFILE AND USER ACCOUNT, SAVE TO THE DATABASE, SEND A JWT TOKEN, AND SEND A CSRF TOKEN TO THE USER. NOTE! MONGOOSE MODEL WILL ALSO SANITIZE ALL THE USER INPUT AGAIN TO PREVENT NOSQL INJECTION ATTACK
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
                    csrfTokenSecret: [savedCSRFTokenSecret._id],
                    forgotPassword: false
                });

                CSRFTokenSecret.findByIdAndUpdate(savedCSRFTokenSecret._id, { user_id: savedUser._id }, (error, docs) => {});
                Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id }, (error, docs) => {});
                
                dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
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
                // END CREATE CSRF TOKEN SECRET, CSRF TOKEN, PROFILE AND USER ACCOUNT, SAVE TO THE DATABASE, SEND A JWT TOKEN, AND SEND A CSRF TOKEN TO THE USER. NOTE! MONGOOSE MODEL WILL ALSO SANITIZE ALL THE USER INPUT AGAIN TO PREVENT NOSQL INJECTION ATTACK
            }
        })
    }
});

const login = tryCatch(async (req, res) => {
    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
    let {username, password} = mongoSanitize.sanitize(req.body);

    if(!username || !password) {
        throw new ErrorResponse(400, "Please provide username and password.", errorCodes.INCOMPLETE_LOGIN_FORM);
    }
    // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

    // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
    username = xss(username);
    password = xss(password);
    // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

    // STEP 3: VALIDATE USER INPUT
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

    const { error } = validationSchema.validate(req.body);

    if (error) {
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_LOGIN);
    }
    // END VALIDATE USER INPUT

    // STEP 4: CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN
    const user = await User.findOne({ username }).populate('csrfTokenSecret'); // return object only
    
    if (!user) {
        throw new ErrorResponse(401, 'Invalid username.', errorCodes.USERNAME_NOT_EXIST_LOGIN);
    }
    // END CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN

    // STEP 5: CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN
    const isMatched = await user.matchPasswords(password);

    if (!isMatched) {
        throw new ErrorResponse(401, 'Invalid password.', errorCodes.PASSWORD_NOT_MATCH_LOGIN);
    }
    // END CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN

    // STEP 6: CREATE CSRF TOKEN BASED ON THE CURRENT USER CSRF TOKEN SECRET AND GRANT ACCESS THE USER AND GIVE JWT TOKEN AND CSRF TOKEN TO THE USER
    const tokens = new Tokens();
    const csrfTokenSecret = user.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    dataToRemoveInsideUserJWTToken.forEach(eachDataToRemove => {
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
    // END CREATE CSRF TOKEN BASED ON THE CURRENT USER CSRF TOKEN SECRET AND GRANT ACCESS THE USER AND GIVE JWT TOKEN AND CSRF TOKEN TO THE USER
});

const logout = tryCatch(async (req, res) => {
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

    return res.status(200).json({status: 'ok'});
});

const forgotPassword = tryCatch(async (req, res) => {
    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
    let {email} = mongoSanitize.sanitize(req.body);

    if(!email) {
        throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM);
    }
    // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

    // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
    email = xss(email);
    // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

    // STEP 3: VALIDATE USER INPUT
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

    if (error) {
        throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD);
    }
    // END VALIDATE USER INPUT

    // STEP 4: CHECK IF EMAIL IS NOT EXIST
    let user = await User.findOne({ email }).populate('csrfTokenSecret');

    if (!user) {
        throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_FORGOT_PASSWORD);
    }
    // END CHECK IF EMAIL IS NOT EXIST

    // STEP 5: SEND EMAIL TO THE USER TO RESET USER PASSWORD ACCOUNT
    await User.findOneAndUpdate({ email }, { forgotPassword: true });

    const tokens = new Tokens();
    const csrfTokenSecret = user.csrfTokenSecret.secret;
    const csrfToken = tokens.create(csrfTokenSecret);

    const ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN = jwt.sign(
        {csrfToken}, 
        process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, 
        {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING}
    );

    const ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN = jwt.sign(
        {email}, 
        process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, 
        {expiresIn: jwtTokensSettings.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING}
    );

    const recoverAccountResetPasswordURL = `${process.env.REACT_URL}/reset-password/${ACCOUNT_RECOVERY_RESET_PASSWORD_JWT_TOKEN}/${ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN}`;
    const html = emailTemplates.recoverAccountResetPasswordEmailTemplate(recoverAccountResetPasswordURL);

    await sendEmail({
        to: email,
        subject: "MERN with Auth - Recovery Account Reset Password",
        text: "You can update your password to recover your account by clicking the link below",
        html,
    });

    return res.status(200).json({ status: 'ok' });
    // END SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT
});

const resetPassword = tryCatch(async (req, res) => {
    let { token, csrfToken, password, repeatPassword } = mongoSanitize.sanitize(req.body);

    if(!token || !csrfToken) {
        throw new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD);
    }else {
        jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, async (error, csrfTokenDecoded) => {
            if(error) {
                throw new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD);
            }else {
                jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, jwtTokenDecoded) => {
                    if(error) {
                        throw new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD);
                    }else {
                        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                        let { email } = mongoSanitize.sanitize(jwtTokenDecoded);
                        let csrfTokenObj = mongoSanitize.sanitize(csrfTokenDecoded);

                        if(!email || !password || !repeatPassword) {
                            throw new ErrorResponse(400, "Please complete the Recovery Account Reset Password Form.", errorCodes.INCOMPLETE_RESET_PASSWORD_FORM);
                        }

                        // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        
                        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
                        email = xss(email);
                        password = xss(password);
                        repeatPassword = xss(repeatPassword);
                        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
        
                        // STEP 3: VALIDATE USER INPUT
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
        
                        if (error) {
                            throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_RESET_PASSWORD);
                        }
                        // END VALIDATE USER INPUT
        
                        // STEP 4: CHECK IF EMAIL IS EXIST
                        let user = await User.findOne({ email }).populate('csrfTokenSecret');
        
                        if (!user) {
                            throw new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_RESET_PASSWORD);
                        }
                        // END CHECK IF EMAIL IS EXIST
        
                        // STEP 5: VERIFY CSRF TOKEN OF THE USER
                        const tokens = new Tokens();
                        if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) {
                            // THE USER HAS CSRF TOKEN BUT INVALID 
                            throw new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_RESET_PASSWORD);
                        }
                        // END VERIFY CSRF TOKEN OF THE USER

                        // STEP 6: UPDATE THE PASSWORD OF THE USER
                        const hashedPassword = await argon2.hash(password);

                        user = await User.findOneAndUpdate({ email }, { password: hashedPassword, forgotPassword: false });

                        if (user) {
                            return res.status(200).json({ status: 'ok'});
                        }
                        // END UPDATE THE PASSWORD OF THE USER
                    }
                });
            }
        });
    }
});

const accountRecoveryResetPasswordVerifyToken = tryCatch(async (req, res) => {
    const { token, csrfToken } = req.body;

    if(!token || !csrfToken) {
        throw new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
    }else {
        jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, async (error, csrfTokenDecoded) => {
            if(error) {
                throw new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
            }else {
                jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, jwtTokenDecoded) => {
                    if(error) {
                        throw new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
                    }else {
                        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                        let { email } = mongoSanitize.sanitize(jwtTokenDecoded);
                        let csrfTokenObj = mongoSanitize.sanitize(csrfTokenDecoded);

                        if(!email) {
                            throw new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
                        }
                        // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

                        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
                        email = xss(email);
                        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

                        // STEP 3: VALIDATE USER INPUT
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

                        if (error) {
                            throw new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
                        }
                        // END VALIDATE USER INPUT

                        // STEP 4: CHECK IF EMAIL IS EXIST AND FORGOT PASSWORD
                        let user = await User.findOne({ email, forgotPassword: true }).populate('csrfTokenSecret');

                        if (!user) {
                            throw new ErrorResponse(400, "Email is not exist or user does not request forgot password.", errorCodes.EMAIL_NOT_EXIST_OR_USER_NOT_REQUEST_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
                        }
                        // END CHECK IF EMAIL IS EXIST AND FORGOT PASSWORD
                        const tokens = new Tokens();

                        if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) {
                            // THE USER HAS CSRF TOKEN BUT INVALID 
                            throw new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN);
                        }

                        return res.status(200).json({ status: 'ok' });
                    }
                });
            }
        })
    }
});

module.exports = {
    user,
    register,
    activate,
    login,
    logout,
    forgotPassword,
    resetPassword,
    accountRecoveryResetPasswordVerifyToken
};