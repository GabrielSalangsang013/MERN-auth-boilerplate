require('dotenv').config()
const User = require('../models/userModel')
const Profile = require('../models/profileModel')
const argon2 = require('argon2')
const jwt = require('jsonwebtoken')
const Joi = require('joi');
const { escape } = require('he');
const xss = require('xss'); // FOR XSS PROTECTION IN REGISTER AND LOGIN PURPOSES
const mongoSanitize = require('express-mongo-sanitize'); // FOR NOSQL INJECTION PROTECTION IN REGISTER AND LOGIN PURPOSES
const JWT_ACCESS_TOKEN_EXPIRATION_STRING = '60s'; // 60 SECONDS FOR JWT 
const COOKIE_ACCESS_TOKEN_EXPIRATION = 60 * 1000; // 60 SECONDS FOR COOKIE JWT TOKEN

const user = async (req, res) => {    
    try {
        return res.status(200).json({status: 'ok', user: req.user})
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'user',
            error: error,
            statusCode: 500
        });
        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'})
    }
}

const register = async (req, res) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, password, repeatPassword, fullName} = mongoSanitize.sanitize(req.body);

        let emptyFields = []

        if(!username) {
            emptyFields.push('username')
        }

        if(!password) {
            emptyFields.push('password')
        }

        if(!repeatPassword) {
            emptyFields.push('repeatPassword')
        }

        if(!fullName) {
            emptyFields.push('fullName')
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({status: 'fail', error: 'Please complete the Registration Form', emptyFields})
        }
        // END SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY

        // STEP 2: SANITIZE THE USER INPUT TO PREVENT XSS ATTACK
        username = xss(username);
        password = xss(password);
        repeatPassword = xss(repeatPassword);
        fullName = xss(fullName);
        // END SANITIZE THE USER INPUT TO PREVENT XSS ATTACK

        // STEP 3: VALIDATE USER INPUT
        const validationSchema = Joi.object({
            username: Joi.string()
                .required()
                .min(4)
                .max(20)
                .pattern(/^[a-zA-Z0-9_]+$/)
                .messages({
                    'string.base': 'Username must be a string',
                    'string.empty': 'Username must not be empty',
                    'string.min': 'Username must be at least 4 characters',
                    'string.max': 'Username must not exceed 20 characters',
                    'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                    'any.required': 'Username is required',
                })
                .custom((value, helpers) => {
                    const forbiddenUsernames = ['admin', 'root', 'superuser'];
                    if (forbiddenUsernames.includes(value.toLowerCase())) {
                        return helpers.error('any.invalid');
                    }
                    return value;
                })
                .custom((value, helpers) => {
                    const sanitizedValue = escape(value);
                    if (sanitizedValue !== value) {
                      return helpers.error('any.invalid');
                    }
                    return value;
                })
                .messages({
                    'any.invalid': 'Username should not contain sensitive information or invalid characters',
                }),
            password: Joi.string()
                .required()
                .min(12)
                .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
                .messages({
                    'string.base': 'Password must be a string',
                    'string.empty': 'Password must not be empty',
                    'string.min': 'Password must be at least 12 characters',
                    'string.pattern.base':
                        'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                    'any.required': 'Password is required',
                })
                .custom((value, helpers) => {
                    const forbiddenPasswords = ['password', '123456789'];
                    if (forbiddenPasswords.includes(value.toLowerCase())) {
                        return helpers.error('any.invalid');
                    }
                    return value;
                })
                .messages({
                    'any.invalid': 'Password should not be commonly used or easily guessable',
                }),
            repeatPassword: Joi.string()
                .valid(Joi.ref('password'))
                .required()
                .messages({
                    'any.only': 'Passwords must match',
                    'any.required': 'Please repeat your password',
                }),
            fullName: Joi.string()
                .required()
                .max(50)
                .pattern(/^[a-zA-Z\s]+$/)
                .custom((value, helpers) => {
                    const sanitizedValue = escape(value);
                    if (sanitizedValue !== value) {
                      return helpers.error('any.invalid');
                    }
                    return value;
                })
                .messages({
                    'string.base': 'Full Name must be a string',
                    'string.empty': 'Full Name must not be empty',
                    'string.max': 'Full Name must not exceed 50 characters',
                    'string.pattern.base': 'Full Name must contain letters only',
                    'any.invalid': 'Full Name contains potentially unsafe characters or invalid characters',
                    'any.required': 'Full Name is required',
                }),
        });

        const { error } = validationSchema.validate(req.body);

        if (error) {
            return res.status(400).json({ status: 'fail', error: error.details[0].message });
        }
        // END VALIDATE USER INPUT

        // STEP 4: CHECK IF USERNAME IS EXIST
        try {
            const user = await User.findOne({ username });

            if (user) {
                return res.status(400).json({ status: 'fail', error: 'Username already exists.' });
            }
        }catch(e) {
            return res.status(500).json({status: 'error', error: 'There is something problem on the server where an error occurred while checking the username. Please try again later.'})
        }
        // END CHECK IF USERNAME IS EXIST

        // STEP 5: CREATE PROFILE AND USER ACCOUNT, SAVE TO THE DATABASE, AND SEND A JWT TOKEN. NOTE! MONGOOSE MODEL WILL ALSO SANITIZE ALL THE USER INPUT AGAIN TO PREVENT NOSQL INJECTION ATTACK
        let profileObj = new Profile({
            fullName: fullName,
            profilePicture: 'https://scontent.fmnl33-2.fna.fbcdn.net/v/t39.30808-6/308857489_125773400264403_7264189266841144710_n.jpg?_nc_cat=104&ccb=1-7&_nc_sid=09cbfe&_nc_eui2=AeFJ4HeZznWkLIm2zixWKb7IAVHx3QoqCnYBUfHdCioKdvwKAQ-8M7VdIUrDhpVz6WFBmhR3NvkmTFjvdJJHLeKY&_nc_ohc=KkGaPRvGXmgAX-6ACpy&_nc_ht=scontent.fmnl33-2.fna&oh=00_AfBVyrakCauKmhPkkQSTk-X28AJSjelNmVnfQlgZpJd2zw&oe=646FC2A0' 
        })

        profileObj.save()
            .then(async savedProfile => {
                const hashedPassword = await argon2.hash(password)
                const user = new User({ 
                    username: username, 
                    password: hashedPassword,
                    profile: [savedProfile._id]
                })
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
                                return res.status(500).json({status: 'error', error: 'There is something problem on the server in searching profile. Please try again later.'})
                            }else{
                                User.findById(savedUser._id) // return object only
                                .populate('profile') // Populate the 'profile' field with the referenced profile documents
                                .exec()
                                .then(foundUser => {
                                    let accessToken = jwt.sign(foundUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: JWT_ACCESS_TOKEN_EXPIRATION_STRING})
                                    res.cookie('access_token', accessToken, { 
                                        httpOnly: true, 
                                        secure: true, 
                                        sameSite: 'none', 
                                        path: '/', 
                                        expires: new Date(new Date().getTime() + COOKIE_ACCESS_TOKEN_EXPIRATION)
                                    })
                                    return res.status(200).json({status: 'ok'})
                                })
                                .catch(error => {
                                    console.log({
                                        fileName: 'v1AuthenticationController.js',
                                        errorDescription: 'There is something problem on the server in searching user.',
                                        errorLocation: 'register',
                                        error: error,
                                        statusCode: 500
                                    });
                                    return res.status(500).json({status: 'error', error: 'There is something problem on the server in searching user. Please try again later.'})
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
                        return res.status(500).json({status: 'error', error: 'There is something problem on the server in creating a user. Please try again later.'})
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
                return res.status(500).json({status: 'error', error: 'There is something problem on the server in creating a profile. Please try again later.'})
            });
        // END CREATE PROFILE AND USER ACCOUNT THEN SAVE TO THE DATABASE
    
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'register',
            error: error,
            statusCode: 500
        });
        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'})
    }
}

const login = async (req, res) => {
    try {
        // STEP 1: SANITIZE THE USER INPUT TO PREVENT NOSQL INJECTION ATTACK AND CHECK IF ALL FIELDS ARE NOT EMPTY
        let {username, password} = mongoSanitize.sanitize(req.body);

        let emptyFields = []

        if(!username) {
            emptyFields.push('username')
        }

        if(!password) {
            emptyFields.push('password')
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({status: 'fail', error: 'Please complete the Login Form', emptyFields})
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
                .min(4)
                .max(20)
                .pattern(/^[a-zA-Z0-9_]+$/)
                .messages({
                    'string.base': 'Username must be a string',
                    'string.empty': 'Username must not be empty',
                    'string.min': 'Username must be at least 4 characters',
                    'string.max': 'Username must not exceed 20 characters',
                    'string.pattern.base': 'Username can only contain letters, numbers, and underscores',
                    'any.required': 'Username is required',
                })
                .custom((value, helpers) => {
                    const forbiddenUsernames = ['admin', 'root', 'superuser'];
                    if (forbiddenUsernames.includes(value.toLowerCase())) {
                        return helpers.error('any.invalid');
                    }
                    return value;
                })
                .custom((value, helpers) => {
                    const sanitizedValue = escape(value);
                    if (sanitizedValue !== value) {
                      return helpers.error('any.invalid');
                    }
                    return value;
                })
                .messages({
                    'any.invalid': 'Username should not contain sensitive information or invalid characters',
                }),
            password: Joi.string()
                .required()
                .min(12)
                .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$/)
                .messages({
                    'string.base': 'Password must be a string',
                    'string.empty': 'Password must not be empty',
                    'string.min': 'Password must be at least 12 characters',
                    'string.pattern.base':
                        'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
                    'any.required': 'Password is required',
                })
                .custom((value, helpers) => {
                    const forbiddenPasswords = ['password', '123456789'];
                    if (forbiddenPasswords.includes(value.toLowerCase())) {
                        return helpers.error('any.invalid');
                    }
                    return value;
                })
                .messages({
                    'any.invalid': 'Password should not be commonly used or easily guessable',
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
        const passwordMatch = await argon2.verify(user.password, password);
        
        if (!passwordMatch) {
            return res.status(401).json({status: 'fail', error: 'Invalid username or password' });
        }
        // END CHECK IF PASSWORD IS MATCH - THE PASSWORD MUST BE MATCH TO BE SUCCESSFULLY LOGIN

        // STEP 6: GRANT ACCESS THE USER AND GIVE JWT TOKEN TO THE USER
        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: JWT_ACCESS_TOKEN_EXPIRATION_STRING})
        
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + COOKIE_ACCESS_TOKEN_EXPIRATION)
        })
        
        return res.status(200).json({status: 'ok', user: user})
        // END GRANT ACCESS THE USER AND GIVE JWT TOKEN TO THE USER
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'login',
            error: error,
            statusCode: 500
        });
        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'})
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
        })
        return res.status(200).json({status: 'ok'})
    }catch(error) {
        console.log({
            fileName: 'v1AuthenticationController.js',
            errorDescription: 'There is something problem on the server.',
            errorLocation: 'logout',
            error: error,
            statusCode: 500
        });
        return res.status(500).json({status: 'error', error: 'There is something problem on the server. Please try again later.'})
    }
}

module.exports = {
    user,
    register,
    login,
    logout
}