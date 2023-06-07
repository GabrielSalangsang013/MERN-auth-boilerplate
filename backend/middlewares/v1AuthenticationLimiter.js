const rateLimit = require('express-rate-limit');
const MongoStore = require('rate-limit-mongo');

const userLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'user-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many user requests, please try again later.',
});

const loginLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'login-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many login requests, please try again later.',
});

const verificationCodeLoginLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
    collectionName: 'verification-code-login-limits', // MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // Time window in milliseconds
    errorHandler: console.error, // Optional error handler
  }),
  max: 100, // Maximum number of requests per time window
  message: 'Too many verification code login requests, please try again later.',
});

const verificationCodeLoginLogoutLimiter = rateLimit({
  store: new MongoStore({
    uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
    collectionName: 'verification-code-login-logout-limits', // MongoDB collection to store rate limit data
    expireTimeMs: 60 * 1000, // Time window in milliseconds
    errorHandler: console.error, // Optional error handler
  }),
  max: 100, // Maximum number of requests per time window
  message: 'Too many verification code login logout requests, please try again later.',
});

const registerLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'register-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many register requests, please try again later.',
});

const activateLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'activate-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many activate requests, please try again later.',
});

const forgotPasswordLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'forgot-password-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many forgot password requests, please try again later.',
});

const resetPasswordLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'reset-password-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many reset password requests, please try again later.',
});

const resetPasswordVerifyTokenLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'reset-password-verify-token-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many reset password verify token requests, please try again later.',
});

const logoutLimiter = rateLimit({
    store: new MongoStore({
      uri: process.env.MONGO_DB_URI_LIMITER, // MongoDB connection URI
      collectionName: 'logout-limits', // MongoDB collection to store rate limit data
      expireTimeMs: 60 * 1000, // Time window in milliseconds
      errorHandler: console.error, // Optional error handler
    }),
    max: 100, // Maximum number of requests per time window
    message: 'Too many logout requests, please try again later.',
});

module.exports = {
    userLimiter,
    loginLimiter,
    verificationCodeLoginLimiter,
    verificationCodeLoginLogoutLimiter,
    registerLimiter,
    activateLimiter,
    forgotPasswordLimiter,
    resetPasswordLimiter,
    resetPasswordVerifyTokenLimiter,
    logoutLimiter
}