const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const { escape } = require('he');
const argon2 = require('argon2');

const userSchema = new Schema({
  username: {
    type: String,
    unique: true,
    trim: true,
    required: [true, 'Username is required'],
    minlength: [4, 'Username must be at least 4 characters'],
    maxlength: [20, 'Username must not exceed 20 characters'],
    match: [/^[a-zA-Z0-9_]+$/, 'Username can only contain letters, numbers, and underscores'],
    validate: [
      {
        validator: function(value) {
          return !/\b(admin|root|superuser)\b/i.test(value);
        },
        message: 'Username should not contain sensitive information',
      },
      {
        validator: function(value) {
          const sanitizedValue = escape(value);
          return sanitizedValue === value;
        },
        message: 'Invalid characters detected',
      },
    ],
  },
  email: {
    type: String,
    unique: true,
    trim: true,
    required: [true, 'Email is required'],
    match: [
      /^(([^<>()[\]\\.,;:\s@"]+(\.[^<>()[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/,
      'Please enter a valid email address',
    ],
    validate: [
      {
        validator: function(value) {
          const sanitizedValue = escape(value);
          return sanitizedValue === value;
        },
        message: 'Invalid email format or potentially unsafe characters',
      },
    ],
  },
  password: {
    type: String,
    required: [true, 'Password is required'],
    minlength: [12, 'Password must be at least 12 characters'],
    match: [
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*()\-_=+{};:,<.>]).+$/,
      'Password must contain at least one uppercase letter, one lowercase letter, one digit, and one special character',
    ],
    validate: [
      {
        validator: function(value) {
          return !/\b(password|123456789)\b/i.test(value);
        },
        message: 'Password should not be commonly used or easily guessable',
      },
    ]
  },
  forgotPassword: {
    type: 'boolean',
    required: false,
    default: false
  },
  verificationCodeLogin: { 
    type: String,
    required: false,
    minlength: [7, 'Verification login code must be 7 characters'],
    maxlength: [7, 'Verification login code must be 7 characters'],
    match: [
      /^(?=.*[a-zA-Z])(?=.*[0-9])[a-zA-Z0-9]{7}$/,
      'Verification login code must be 7 characters and contain only numbers and letters',
    ],
    validate: [
      {
        validator: function(value) {
          return !/\b(admin|root|superuser)\b/i.test(value);
        },
        message: 'Verification login code should not contain sensitive information',
      },{
        validator: function(value) {
          const sanitizedValue = escape(value);
          return sanitizedValue === value;
        },
        message: 'Invalid verification login code format or potentially unsafe characters',
      },
    ]
  },
  csrfTokenSecret: {
    type: Schema.Types.ObjectId,
    ref: 'CSRFTokenSecret',
    required: true
  },
  profile: {
    type: Schema.Types.ObjectId,
    ref: 'Profile',
    required: true
  }
}, { timestamps: true });

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) {
    return next();
  }

  try {
    const hashedPassword = await argon2.hash(this.password);
    this.password = hashedPassword;
    return next();
  } catch (error) {
    return next(error);
  }
});

userSchema.methods.matchPasswords = async function (password) {
  return await argon2.verify(this.password, password);
};

userSchema.methods.matchVerificationCodeLogin = async function (verificationCodeLogin) {
  return await argon2.verify(this.verificationCodeLogin, verificationCodeLogin);
};

module.exports = mongoose.model('User', userSchema);