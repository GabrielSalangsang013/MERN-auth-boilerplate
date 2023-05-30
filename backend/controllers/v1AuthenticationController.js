require('dotenv').config();
const User = require('../models/userModel');
const Profile = require('../models/profileModel');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { escape } = require('he');
const xss = require('xss'); // FOR XSS PROTECTION IN REGISTER AND LOGIN PURPOSES
const mongoSanitize = require('express-mongo-sanitize'); // FOR NOSQL INJECTION PROTECTION IN REGISTER AND LOGIN PURPOSES
const frontendConfig = require('../config/frontend');
const sendEmail = require("../utils/sendEmail");
const ACCESS_TOKEN_EXPIRATION = 60 * 1000;
const argon2 = require('argon2');

const user = async (req, res) => {    
    try {
        return res.status(200).json({status: 'ok', user: req.user});
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'user',
            error: error,
            statusCode: 500
        });
        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const register = async (req, res) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, email, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);

        let emptyFields = [];

        if(!username) {
            emptyFields.push('username');
        }

        if(!email) {
            emptyFields.push('email');
        }

        if(!password) {
            emptyFields.push('password');
        }

        if(!repeatPassword) {
            emptyFields.push('repeatPassword');
        }

        if(!fullName) {
            emptyFields.push('fullName');
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({status: 'fail', error: 'Please complete the Registration Form', emptyFields});
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
            return res.status(400).json({ status: 'fail', error: error.details[0].message });
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF USERNAME IS EXIST
        try {
            const user = await User.findOne({ username });

            if (user) {
                return res.status(400).json({ status: 'fail', error: 'Username already exist.' });
            }
        }catch(error) {
            return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the username. Please try again later.'});
        }
        // END CHECK IF USERNAME IS EXIST

        // STEP 5: CHECK IF EMAIL IS EXIST
        try {
            const user = await User.findOne({ email });

            if (user) {
                return res.status(400).json({ status: 'fail', error: 'Email already exist.' });
            }
        }catch(error) {
            return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email. Please try again later.'});
        }
        // END CHECK IF EMAIL IS EXIST

        // STEP 6: SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT
        const ACCOUNT_ACTIVATION_TOKEN = jwt.sign({username, email, password, repeatPassword, fullName}, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, {expiresIn: process.env.ACCOUNT_ACTIVATION_EXPIRES_IN_STRING});
        const activateAccountURL = `${frontendConfig.uri}/activate/${ACCOUNT_ACTIVATION_TOKEN}`;
        const html = `
            <h1>Your account will be activated by clicking the link below</h1>
            <hr />
            <a href=${activateAccountURL} clicktracking=off>${activateAccountURL}</a>
        `;

        try {
            await sendEmail({
                to: email,
                subject: "MERN with Auth - Account Activation",
                text: "Your account will be activated by clicking the link below",
                html,
            });

            return res.status(200).json({ status: 'ok' });
        } catch (error) {
            console.log({
                fileName: 'v1AuthenticationController.js',
                errorDescription: 'There is something problem on the server in sending the email account activation.',
                errorLocation: 'register',
                error: error,
                statusCode: 500
            });

            return res.status(500).json({status: 'error', error: 'There is something problem on the server in sending the email account activation. Please try again later.'});
        }
        // END SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'register',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const activate = async (req, res) => {
    try {
        const { token } = req.body;

        if(token) {
            jwt.verify(token, process.env.ACCOUNT_ACTIVATION_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return res.status(401).json({status: 'fail', error: 'Expired link or Invalid Token. Please sign up again.'});
                }else {
                    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                    let { username, email, password, repeatPassword, fullName } = mongoSanitize.sanitize(jwt.decode(token));

                    let emptyFields = [];

                    if(!username) {
                        emptyFields.push('username');
                    }

                    if(!email) {
                        emptyFields.push('email');
                    }

                    if(!password) {
                        emptyFields.push('password');
                    }

                    if(!repeatPassword) {
                        emptyFields.push('repeatPassword');
                    }

                    if(!fullName) {
                        emptyFields.push('fullName');
                    }

                    if(emptyFields.length > 0) {
                        return res.status(400).json({status: 'fail', error: 'Please complete the Registration Form', emptyFields});
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
                        return res.status(400).json({ status: 'fail', error: error.details[0].message });
                    }
                    // END VALIDATE USER INPUT

                    // STEP 4: CHECK IF USERNAME IS EXIST
                    try {
                        const user = await User.findOne({ username });

                        if (user) {
                            return res.status(400).json({ status: 'fail', error: 'Username already exist.' });
                        }
                    }catch(error) {
                        return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the username. Please try again later.'});
                    }
                    // END CHECK IF USERNAME IS EXIST

                    // STEP 5: CHECK IF EMAIL IS EXIST
                    try {
                        const user = await User.findOne({ email });

                        if (user) {
                            return res.status(400).json({ status: 'fail', error: 'Email already exist.' });
                        }
                    }catch(error) {
                        return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email. Please try again later.'});
                    }
                    // END CHECK IF EMAIL IS EXIST

                    // STEP 6: CREATE PROFILE AND USER ACCOUNT, SAVE TO THE DATABASE, AND SEND A JWT TOKEN. NOTE! MONGOOSE MODEL WILL ALSO SANITIZE ALL THE USER INPUT AGAIN TO PREVENT NOSQL INJECTION ATTACK
                    let profileObj = new Profile({
                        fullName: fullName,
                        profilePicture: 'https://res.cloudinary.com/dgo6vnzjl/image/upload/c_fill,q_50,w_150/v1685085963/default_male_avatar_xkpekq.webp' 
                    });

                    profileObj.save()
                        .then(async savedProfile => {
                            const user = User({ 
                                username: username, 
                                email: email, 
                                password: password,
                                profile: [savedProfile._id]
                            });
                            
                            // THE USER WILL BE SAVED. BEFORE SAVING TO THE DATABASE
                            // THE USER WILL UNDER GO FIRST TO THE USER MODEL MONGOOSE VALIDATION WHICH IS FINAL VALIDATION
                            // THEN HASH THE PASSWORD THEN SAVE TO THE DATABASE
                            user.save()
                                .then(async savedUser => {
                                    Profile.findByIdAndUpdate(savedProfile._id, { user_id: savedUser._id }, (error, docs) => {
                                        if(error) {
                                            console.log({
                                                fileName: 'v1AuthenticationController.js',
                                                errorDescription: 'There is something problem on the server in searching profile.',
                                                errorLocation: 'register',
                                                error: error,
                                                statusCode: 500
                                            });
                                            return res.status(500).json({status: 'error', error: 'There is something problem on the server in searching profile. Please try again later.'});
                                        }else{
                                            User.findById(savedUser._id) // return object only
                                                .populate('profile') // Populate the 'profile' field with the referenced profile documents
                                                .exec()
                                                .then(foundUser => {
                                                    foundUser.password = undefined;
                                                    let accessToken = jwt.sign(foundUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: process.env.ACCESS_TOKEN_EXPIRATION_STRING});
                                                    res.cookie('access_token', accessToken, { 
                                                        httpOnly: true, 
                                                        secure: true, 
                                                        sameSite: 'none', 
                                                        path: '/', 
                                                        expires: new Date(new Date().getTime() + ACCESS_TOKEN_EXPIRATION)
                                                    });
                                                    return res.status(200).json({status: 'ok'});
                                                })
                                                .catch(error => {
                                                    console.log({
                                                        fileName: 'v1AuthenticationController.js',
                                                        errorDescription: 'There is something problem on the server in searching user.',
                                                        errorLocation: 'register',
                                                        error: error,
                                                        statusCode: 500
                                                    });
                                                    return res.status(500).json({status: 'error', error: 'There is something problem on the server in searching user. Please try again later.'});
                                                });
                                        }
                                    });
                                })
                                .catch(error => {
                                    console.log({
                                        fileName: 'v1AuthenticationController.js',
                                        errorDescription: 'There is something problem on the server in creating a user.',
                                        errorLocation: 'register',
                                        error: error,
                                        statusCode: 500
                                    });
                                    return res.status(500).json({status: 'error', error: 'There is something problem on the server in creating a user. Please try again later.'});
                                });
                        })
                        .catch(error => {
                            console.log({
                                fileName: 'v1AuthenticationController.js',
                                errorDescription: 'There is something problem on the server in creating a profile.',
                                errorLocation: 'register',
                                error: error,
                                statusCode: 500
                            });
                            return res.status(500).json({status: 'error', error: 'There is something problem on the server in creating a profile. Please try again later.'});
                        });
                    // END CREATE PROFILE AND USER ACCOUNT THEN SAVE TO THE DATABASE
                }
            })
        }else {
            return res.status(401).json({status: 'error', error: 'No token'});
        }
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'activate',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const login = async (req, res) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, password} = mongoSanitize.sanitize(req.body);

        let emptyFields = [];

        if(!username) {
            emptyFields.push('username');
        }

        if(!password) {
            emptyFields.push('password');
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({status: 'fail', error: 'Please complete the Login Form', emptyFields});
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
            return res.status(400).json({ status: 'fail', error: error.details[0].message });
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN
        const user = await User.findOne({ username }).populate('profile'); // return object only
        
        if (!user) {
            return res.status(401).json({status: 'fail', error: 'Invalid username or password' });
        }
        // END CHECK IF USERNAME IS EXIST - THE USERNAME MUST EXIST TO BE SUCCESSFULLY LOGIN

        // STEP 5: CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN
        const isMatched = await user.matchPasswords(password);

        if (!isMatched) {
            return res.status(401).json({status: 'fail', error: 'Invalid username or password' });
        }
        // END CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN

        // STEP 6: GRANT ACCESS THE USER AND GIVE JWT TOKEN TO THE USER
        user.password = undefined;
        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: process.env.ACCESS_TOKEN_EXPIRATION_STRING});
        
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + ACCESS_TOKEN_EXPIRATION)
        });

        return res.status(200).json({status: 'ok', user: user});
        // END GRANT ACCESS THE USER AND GIVE JWT TOKEN TO THE USER
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'login',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const logout = async (req, res) => {
    try {
        res.cookie('access_token', 'expiredtoken', {
            httpOnly: true,
            secure: true,
            sameSite: 'none', 
            path: '/', 
            expires: new Date(Date.now() + 10000)
        });

        return res.status(200).json({status: 'ok'});
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'logout',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const forgotPassword = async (req, res) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {email} = mongoSanitize.sanitize(req.body);

        let emptyFields = [];

        if(!email) {
            emptyFields.push('email');
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({ status: 'fail', error: 'Please complete the Recovery Account Form', emptyFields});
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
            return res.status(400).json({ status: 'fail', error: error.details[0].message });
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF EMAIL IS NOT EXIST
        try {
            const user = await User.findOne({ email });

            if (!user) {
                return res.status(400).json({ status: 'fail', error: 'Email is not exist.' });
            }
        }catch(error) {
            return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email. Please try again later.'});
        }
        // END CHECK IF EMAIL IS NOT EXIST

        // STEP 5: SEND EMAIL TO THE USER TO RESET USER PASSWORD ACCOUNT
        const ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN = jwt.sign({email}, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, {expiresIn: process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING});
        const recoverAccountResetPasswordURL = `${frontendConfig.uri}/reset-password/${ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN}`;
        const html = `
            <h1>You can update your password to recover your account by clicking the link below</h1>
            <hr />
            <a href=${recoverAccountResetPasswordURL} clicktracking=off>${recoverAccountResetPasswordURL}</a>
        `;

        try {
            await sendEmail({
                to: email,
                subject: "MERN with Auth - Recovery Account Reset Password",
                text: "You can update your password to recover your account by clicking the link below",
                html,
            });

            return res.status(200).json({ status: 'ok' });
        } catch (error) {
            console.log({
                fileName: 'v1AuthenticationController.js',
                errorDescription: 'There is something problem on the server in sending the email account recovery reset password.',
                errorLocation: 'forgotPassword',
                error: error,
                statusCode: 500
            });

            return res.status(500).json({status: 'error', error: 'There is something problem on the server in sending the email account recovery reset password. Please try again later.'});
        }
        // END SEND EMAIL TO THE USER TO ACTIVATE USER ACCOUNT

    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'forgotPassword',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
}

const resetPassword = async (req, res) => {
    try {
        let { token, password, repeatPassword } = mongoSanitize.sanitize(req.body);

        if(token) {
            jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return res.status(401).json({status: 'fail', error: 'Expired link or Invalid Token. Please enter your email again.'});
                }else {
                    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                    let { email } = mongoSanitize.sanitize(jwt.decode(token));
    
                    let emptyFields = [];
    
                    if(!email) {
                        emptyFields.push('email');
                    }
    
                    if(!password) {
                        emptyFields.push('password');
                    }
    
                    if(!repeatPassword) {
                        emptyFields.push('repeatPassword');
                    }
    
                    if(emptyFields.length > 0) {
                        return res.status(400).json({ status: 'fail', error: 'Please complete the Recovery Account Reset Password Form', emptyFields});
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
                        return res.status(400).json({ status: 'fail', error: error.details[0].message });
                    }
                    // END VALIDATE USER INPUT
    
                    // STEP 4: CHECK IF EMAIL IS NOT EXIST
                    try {
                        const user = await User.findOne({ email });
    
                        if (!user) {
                            return res.status(400).json({ status: 'fail', error: 'Email is not exist.' });
                        }
                    }catch(error) {
                        return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email. Please try again later.'});
                    }
                    // END CHECK IF EMAIL IS NOT EXIST
    
                    // STEP 5: UPDATE THE PASSWORD OF THE USER
                    try {
                        const hashedPassword = await argon2.hash(password);
                        const user = await User.findOneAndUpdate({ email }, { password: hashedPassword });
                        if (user) {
                            return res.status(200).json({ status: 'ok'});
                        }
                    }catch(error) {
                        console.log({
                            fileName: 'v1AuthenticationController.js',
                            errorDescription: 'There is something problem on the server where an error occurred while checking the email and update the password.',
                            errorLocation: 'resetPassword',
                            error: error,
                            statusCode: 500
                        });
    
                        return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email and update the password. Please try again later.'});
                    }
                    // END UPDATE THE PASSWORD OF THE USER
                }
            })
        }else {
            return res.status(401).json({status: 'error', error: 'No token'});
        }
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'resetPassword',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
    }
};

const accountRecoveryResetPasswordVerifyToken = async (req, res) => {
    try {
        const { token } = req.body;
        if(token) {
            jwt.verify(token, process.env.ACCOUNT_RECOVERY_RESET_PASSWORD_TOKEN_SECRET, async (error, decoded) => {
                if(error) {
                    return res.status(401).json({status: 'fail', error: 'Expired link or Invalid Token. Please enter your email again.'});
                }else {
                    // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
                    let { email } = mongoSanitize.sanitize(jwt.decode(token));

                    let emptyFields = [];

                    if(!email) {
                        emptyFields.push('email');
                    }

                    if(emptyFields.length > 0) {
                        return res.status(400).json({ status: 'fail', error: 'Please complete the Recovery Account Form', emptyFields});
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
                        return res.status(400).json({ status: 'fail', error: error.details[0].message });
                    }
                    // END VALIDATE USER INPUT

                    // STEP 4: CHECK IF EMAIL IS NOT EXIST
                    try {
                        const user = await User.findOne({ email });

                        if (!user) {
                            return res.status(400).json({ status: 'fail', error: 'Email is not exist.' });
                        }
                    }catch(error) {
                        console.log({
                            fileName: 'v1AuthenticationController.js',
                            errorDescription: 'There is something problem on the server where an error occurred while checking the email. Please try again later.',
                            errorLocation: 'accountRecoveryResetPasswordVerifyToken',
                            error: error,
                            statusCode: 500
                        });

                        return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the email. Please try again later.'});
                    }
                    // END CHECK IF EMAIL IS NOT EXIST

                    return res.status(200).json({ status: 'ok' });
                }
            })
        }else {
            return res.status(401).json({status: 'error', error: 'No token'});
        }
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'accountRecoveryResetPasswordVerifyToken',
            error: error,
            statusCode: 500
        });

        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'});
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