require('dotenv').config()
const User = require('../models/userModel')
const Profile = require('../models/profileModel')
const argon2 = require('argon2')
const jwt = require('jsonwebtoken')

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
        const {username, password, fullName} = req.body

        let emptyFields = []

        if(!username) {
            emptyFields.push('username')
        }

        if(!password) {
            emptyFields.push('password')
        }

        if(!fullName) {
            emptyFields.push('fullName')
        }

        if(emptyFields.length > 0) {
            return res.status(400).json({status: 'fail', error: 'Please complete the Registration Form', emptyFields})
        }

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
                                    let accessToken = jwt.sign(foundUser.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: '60s'})
                                    res.cookie('access_token', accessToken, { 
                                        httpOnly: true, 
                                        secure: true, 
                                        sameSite: 'none', 
                                        path: '/', 
                                        expires: new Date(new Date().getTime() + 60 * 1000)
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
        const { username, password } = req.body;
        const user = await User.findOne({ username }).populate('profile'); // return object only
        
        if (!user) {
            return res.status(401).json({status: 'fail', error: 'Invalid username or password' });
        }
        
        const passwordMatch = await argon2.verify(user.password, password);
        
        if (!passwordMatch) {
            return res.status(401).json({status: 'fail', error: 'Invalid username or password' });
        }

        let accessToken = jwt.sign(user.toJSON(), process.env.ACCESS_TOKEN_SECRET, {expiresIn: '60s'})
        res.cookie('access_token', accessToken, { 
            httpOnly: true, 
            secure: true, 
            sameSite: 'none', 
            path: '/', 
            expires: new Date(new Date().getTime() + 60 * 1000)
        })
        return res.status(200).json({status: 'ok', user: user})
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