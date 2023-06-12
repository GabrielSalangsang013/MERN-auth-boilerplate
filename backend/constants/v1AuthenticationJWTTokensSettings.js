exports.JWT_ACCESS_TOKEN_EXPIRATION_STRING = "30m"; // HOW LONG THE USER CAN BE AUTHENTICATED WHEN SUCCESS IN LOGIN?

// ---------------- FOR EMAIL ----------------

exports.JWT_ACCOUNT_ACTIVATION_EXPIRES_IN_STRING = "5m"; // HOW LONG THE EMAIL ACTIVATION LINK TO BE EXPIRED
exports.JWT_ACCOUNT_RECOVERY_RESET_PASSWORD_EXPIRES_IN_STRING = "5m"; // HOW LONG THE EMAIL ACCOUNT RECOVERY RESET PASSWORD LINK TO BE EXPIRED

// ---------------- FOR MULTI FACTOR AUTHENTICATION LOGIN CODE ----------------
exports.JWT_MFA_LOGIN_TOKEN_EXPIRATION_STRING = "5m"; // HOW LONG THE MULTI FACTOR AUTHENTICATION TO BE ENDED BEFORE LOGIN AGAIN?