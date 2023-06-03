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
// ----------------- UTILITIES -----------------

// ----------------- CONSTANTS -----------------
const emailTemplates = require('../constants/v1AuthenticationEmailTemplates'); // EMAIL TEMPLATES
const errorCodes = require('../constants/v1AuthenticationErrorCodes'); // ALL ERROR CODES
const cookiesSettings = require('../constants/v1AuthenticationCookiesSettings'); // ALL COOKIES SETTINGS
const jwtTokensSettings = require('../constants/v1AuthenticationJWTTokensSettings'); // ALL JWT TOKEN SETTINGS
// ----------------- CONSTANTS -----------------

const user = async (req, res, next) => {    
    try {
        return res.status(200).json({status: 'ok', user: req.user});
    }catch(error) {
        next(error);
    }
}

const register = async (req, res, next) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, email, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);

        if(!username || !email || !password || !repeatPassword || !fullName) {
            return next(new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM));
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
            return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER));
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF USERNAME IS EXIST
        let user = await User.findOne({ username });

        if (user) {
            return next(new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER));
        }
        // END CHECK IF USERNAME IS EXIST

        // STEP 5: CHECK IF EMAIL IS EXIST
        user = await User.findOne({ email });

        if (user) {
            return next(new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER));
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
    }catch(error) {
        next(error);
    }
}

const activate = async (req, res, next) => {
    try {
        const { token } = req.body;

        if(!token){
            return next(new ErrorResponse(401, "No Activate JWT Token", errorCodes.NO_ACCOUNT_ACTIVATION_JWT_TOKEN));
        }else {
            jwt.verify(token, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return next(new ErrorResponse(401, "Expired link or Invalid Activate JWT Token. Please sign up again.", errorCodes.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN));
                }else {
                    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(decoded);

                    if(!username || !email || !password || !repeatPassword || !fullName) {
                        return next(new ErrorResponse(400, "Please complete the Registration Form.", errorCodes.INCOMPLETE_REGISTER_FORM_ACTIVATE));
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
                        return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_REGISTER_ACTIVATE));
                    }
                    // END VALIDATE USER INPUT

                    // STEP 4: CHECK IF USERNAME IS EXIST
                    let user = await User.findOne({ username });

                    if (user) {
                        return next(new ErrorResponse(400, "Username already exist.", errorCodes.USERNAME_EXIST_REGISTER_ACTIVATE));
                    }
                    // END CHECK IF USERNAME IS EXIST

                    // STEP 5: CHECK IF EMAIL IS EXIST
                    user = await User.findOne({ email });

                    if (user) {
                        return next(new ErrorResponse(400, "Email already exist.", errorCodes.EMAIL_EXIST_REGISTER_ACTIVATE));
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
                    User.findById(savedUser._id).populate('profile').populate('csrfTokenSecret').exec()
                        .then(foundUser => {
                            foundUser.password = undefined;
                            let accessToken = jwt.sign(foundUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: jwtTokensSettings.JWT_ACCESS_TOKEN_EXPIRATION_STRING});
                            
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
                    // END CREATE CSRF TOKEN SECRET, CSRF TOKEN, PROFILE AND USER ACCOUNT, SAVE TO THE DATABASE, SEND A JWT TOKEN, AND SEND A CSRF TOKEN TO THE USER. NOTE! MONGOOSE MODEL WILL ALSO SANITIZE ALL THE USER INPUT AGAIN TO PREVENT NOSQL INJECTION ATTACK
                }
            })
        }
    }catch(error) {
        next(error);
    }
}

const login = async (req, res, next) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, password} = mongoSanitize.sanitize(req.body);

        if(!username || !password) {
            return next(new ErrorResponse(400, "Please provide username and password.", errorCodes.INCOMPLETE_LOGIN_FORM));
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
            return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_LOGIN));
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN
        const user = await User.findOne({ username }).populate('profile').populate('csrfTokenSecret'); // return object only
        
        if (!user) {
            return next(new ErrorResponse(401, 'Invalid username.', errorCodes.USERNAME_NOT_EXIST_LOGIN));
        }
        // END CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN

        // STEP 5: CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN
        const isMatched = await user.matchPasswords(password);

        if (!isMatched) {
            return next(new ErrorResponse(401, 'Invalid password.', errorCodes.PASSWORD_NOT_MATCH_LOGIN));
        }
        // END CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN

        // STEP 6: CREATE CSRF TOKEN BASED ON THE CURRENT USER CSRF TOKEN SECRET AND GRANT ACCESS THE USER AND GIVE JWT TOKEN AND CSRF TOKEN TO THE USER
        const tokens = new Tokens();
        const csrfTokenSecret = user.csrfTokenSecret.secret;
        const csrfToken = tokens.create(csrfTokenSecret);
        
        user.password = undefined;

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
    }catch(error) {
        next(error);
    }
}

const logout = async (req, res, next) => {
    try {
        res.cookie('access_token', 'expiredtoken', {
            httpOnly: true,
            secure: true,
            sameSite: 'strict', 
            path: '/', 
            expires: new Date(Date.now() + 10000)
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
    }catch(error) {
        next(error);
    }
}

const forgotPassword = async (req, res, next) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {email} = mongoSanitize.sanitize(req.body);

        if(!email) {
            return next(new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM));
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
            return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD));
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF EMAIL IS NOT EXIST
        let user = await User.findOne({ email }).populate('csrfTokenSecret');

        if (!user) {
            return next(new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_FORGOT_PASSWORD));
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
    }catch(error) {
        next(error);
    }
}

const resetPassword = async (req, res, next) => {
    try {
        let { token, csrfToken, password, repeatPassword } = mongoSanitize.sanitize(req.body);

        if(!token || !csrfToken) {
            return next(new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD));
        }else {
            jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return next(new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD));
                }else {
                    jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, decoded) => {
                        if(error) {
                            return next(new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD));
                        }else {
                            // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                            let { email } = mongoSanitize.sanitize(decoded);
                            let csrfTokenObj = jwt.decode(csrfToken);

                            if(!email || !password || !repeatPassword) {
                                return next(new ErrorResponse(400, "Please complete the Recovery Account Reset Password Form.", errorCodes.INCOMPLETE_RESET_PASSWORD_FORM));
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
                                return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_RESET_PASSWORD));
                            }
                            // END VALIDATE USER INPUT
            
                            // STEP 4: CHECK IF EMAIL IS EXIST
                            let user = await User.findOne({ email }).populate('csrfTokenSecret');
            
                            if (!user) {
                                return next(new ErrorResponse(400, "Email is not exist.", errorCodes.EMAIL_NOT_EXIST_RESET_PASSWORD));
                            }
                            // END CHECK IF EMAIL IS EXIST
            
                            const tokens = new Tokens();

                            if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) {
                                // THE USER HAS CSRF TOKEN BUT INVALID 
                                return next(new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_RESET_PASSWORD));
                            }

                            // STEP 5: UPDATE THE PASSWORD OF THE USER
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
    }catch(error) {
        next(error);
    }
};

const accountRecoveryResetPasswordVerifyToken = async (req, res, next) => {
    try {
        const { token, csrfToken } = req.body;

        if(!token || !csrfToken) {
            return next(new ErrorResponse(401, "No JWT Token or CSRF Token.", errorCodes.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
        }else {
            jwt.verify(csrfToken, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_CSRF_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return next(new ErrorResponse(401, "Expired link or Invalid CSRF Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
                }else {
                    jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, decoded) => {
                        if(error) {
                            return next(new ErrorResponse(401, "Expired link or Invalid JWT Token. Please enter your email again.", errorCodes.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
                        }else {
                            // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                            let { email } = mongoSanitize.sanitize(jwt.decode(token));
                            let csrfTokenObj = mongoSanitize.sanitize(jwt.decode(csrfToken));

                            if(!email) {
                                return next(new ErrorResponse(400, "Please complete the Forgot Password Form.", errorCodes.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
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
                                return next(new ErrorResponse(400, error.details[0].message, errorCodes.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
                            }
                            // END VALIDATE USER INPUT

                            // STEP 4: CHECK IF EMAIL IS EXIST AND FORGOT PASSWORD
                            let user = await User.findOne({ email, forgotPassword: true }).populate('csrfTokenSecret');

                            if (!user) {
                                return next(new ErrorResponse(400, "Email is not exist or user does not request forgot password.", errorCodes.EMAIL_NOT_EXIST_OR_USER_NOT_REQUEST_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
                            }
                            // END CHECK IF EMAIL IS EXIST AND FORGOT PASSWORD
                            const tokens = new Tokens();

                            if (!tokens.verify(user.csrfTokenSecret.secret, csrfTokenObj.csrfToken)) {
                                // THE USER HAS CSRF TOKEN BUT INVALID 
                                return next(new ErrorResponse(403, "You are forbidden. Invalid CSRF token.", errorCodes.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN));
                            }

                            return res.status(200).json({ status: 'ok' });
                        }
                    });
                }
            })
        }
    }catch(error) {
        next(error);
    }
}

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