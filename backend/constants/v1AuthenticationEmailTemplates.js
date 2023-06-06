// -------------------- REGISTER ACCOUNT ACTIVATION EMAIL TEMPLATE --------------------

const ACCOUNT_ACTIVATION_EMAIL_SUBJECT = "MERN with Auth - Account Activation";
const ACCOUNT_ACTIVATION_EMAIL_TEXT = "Your account will be activated by clicking the link below";
const ACCOUNT_ACTIVATION_EMAIL_HTML = (activateAccountURL) => {
    return `
        <h1>Your account will be activated by clicking the link below</h1>
        <a href=${activateAccountURL} clicktracking="off">
            <button style="padding: 8px 16px; background-color: skyblue; color: white; border: 0px;">Activate my Account</button>
        </a>
    `;
}

// ------------- RECOVER ACCOUNT RESET PASSWORD EMAIL TEMPLATE -------------

const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT = "MERN with Auth - Recovery Account Reset Password";
const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT = "You can update your password to recover your account by clicking the link below";
const RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML = (recoverAccountResetPasswordURL) => {
    return `
        <h1>You can update your password to recover your account by clicking the link below</h1>
        <a href=${recoverAccountResetPasswordURL} clicktracking="off">
            <button style="padding: 8px 16px; background-color: skyblue; color: white; border: 0px;">Update my Password</button>
        </a>
    `;
}

// ------------- MULTI FACTOR AUTHENTICATION LOGIN ACCOUNT EMAIL TEMPLATE -------------

const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_SUBJECT = "MERN with Auth - MULTI Factor Authentication Verification Login Code ";
const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_TEXT = "Here's the code for your authentication.";
const MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_HTML = (sendVerificationCodeLogin) => {
    return `
        <h1>Don't share the code to anyone!</h1>
        <p>Here's the code: ${sendVerificationCodeLogin}</p>
    `;
}

module.exports = {
    ACCOUNT_ACTIVATION_EMAIL_SUBJECT,
    ACCOUNT_ACTIVATION_EMAIL_TEXT,
    ACCOUNT_ACTIVATION_EMAIL_HTML,

    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT,
    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT,
    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML,

    MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_SUBJECT,
    MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_TEXT,
    MULTI_FACTOR_AUTHENTICATION_LOGIN_ACCOUNT_CODE_EMAIL_HTML
}