// ------------- AUTHENTICATE JWT TOKEN MIDDLEWARE -------------
exports.NO_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN = 300;
exports.INVALID_JWT_TOKEN_AUTHENTICATE_JWT_TOKEN = 301;
exports.NO_USER_FOUND_IN_DATABASE_INSIDE_JWT_DECODED_TOKEN_AUTHENTICATE_JWT_TOKEN = 302;

// ------------- VERIFY PRIVATE CSRF TOKEN MIDDLEWARE -------------
exports.NO_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN = 303;
exports.INVALID_CSRF_TOKEN_VERIFY_PRIVATE_CSRF_TOKEN = 304;

// ------------- VERIFY PUBLIC CSRF TOKEN MIDDLEWARE -------------
exports.NO_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN = 305;
exports.INVALID_CSRF_TOKEN_VERIFY_PUBLIC_CSRF_TOKEN = 306;

// ------------- LOGIN CONTROLLER -------------
exports.INCOMPLETE_LOGIN_FORM = 307;
exports.INVALID_USER_INPUT_LOGIN = 308;
exports.USERNAME_NOT_EXIST_LOGIN = 309; 
exports.PASSWORD_NOT_MATCH_LOGIN = 310; 

// ------------- VERIFICATION CODE LOGIN CONTROLLER -------------
exports.INCOMPLETE_LOGIN_FORM_VERIFICATION_CODE_LOGIN = 311;
exports.INVALID_OR_EXPIRED_MULTI_FACTOR_AUTHENTICATION_LOGIN_CODE = 312;
exports.INVALID_USER_INPUT_VERIFICATION_CODE_LOGIN = 313;
exports.USER_NOT_EXIST_VERIFICATION_CODE_LOGIN = 314;
exports.VERIFICATION_CODE_LOGIN_NOT_MATCH = 315;
exports.EXPIRED_VERIFICATION_CODE_LOGIN = 316;

// ------------- REGISTER CONTROLLER -------------
exports.INCOMPLETE_REGISTER_FORM = 317;
exports.INVALID_USER_INPUT_REGISTER = 318;
exports.USERNAME_EXIST_REGISTER = 319;
exports.EMAIL_EXIST_REGISTER = 320;

// ------------- ACTIVATE CONTROLLER -------------
exports.INCOMPLETE_REGISTER_FORM_ACTIVATE = 321;
exports.INVALID_USER_INPUT_REGISTER_ACTIVATE = 322;
exports.USERNAME_EXIST_REGISTER_ACTIVATE = 323;
exports.EMAIL_EXIST_REGISTER_ACTIVATE = 324;
exports.EXPIRED_ACCOUNT_ACTIVATION_JWT_TOKEN_OR_INVALID_ACCOUNT_ACTIVATION_JWT_TOKEN = 325;
exports.NO_ACCOUNT_ACTIVATION_JWT_TOKEN = 326;

// ------------- FORGOT PASSWORD CONTROLLER -------------
exports.INCOMPLETE_FORGOT_PASSWORD_FORM = 327;
exports.INVALID_USER_INPUT_FORGOT_PASSWORD = 328;
exports.EMAIL_NOT_EXIST_FORGOT_PASSWORD = 329;

// ------------- RESET PASSWORD CONTROLLER -------------
exports.NO_JWT_TOKEN_OR_CSRF_TOKEN_RESET_PASSWORD = 330;
exports.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_RESET_PASSWORD = 331;
exports.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_RESET_PASSWORD = 332;
exports.INCOMPLETE_RESET_PASSWORD_FORM = 333;
exports.PASSWORD_REPEAT_PASSWORD_NOT_MATCH_RESET_PASSWORD_FORM = 334;
exports.INVALID_USER_INPUT_RESET_PASSWORD = 335;
exports.EMAIL_NOT_EXIST_RESET_PASSWORD = 336;
exports.INVALID_CSRF_TOKEN_RESET_PASSWORD = 337;

// ------------- ACCOUNT RECOVERY RESET PASSWORD VERIFY TOKEN CONTROLLER -------------
exports.NO_JWT_TOKEN_OR_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 338;
exports.EXPIRED_LINK_OR_INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 339;
exports.EXPIRED_LINK_OR_INVALID_JWT_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 340;
exports.INCOMPLETE_FORGOT_PASSWORD_FORM_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 341;
exports.INVALID_USER_INPUT_FORGOT_PASSWORD_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 342;
exports.INVALID_CSRF_TOKEN_ACCOUNT_RECOVERY_RESET_PASSWORD_VERIFY_TOKEN = 343;

// ------------- MODEL MONGOOSE VALIDATION ERROR -------------
exports.MONGOOSE_VALIDATION_ERROR = 499;

// ------------- SERVER ERROR -------------
exports.SERVER_ERROR = 500;

