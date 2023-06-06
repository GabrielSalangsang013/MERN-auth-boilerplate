// -------------------- REGISTER ACCOUNT ACTIVATION EMAIL TEMPLATE --------------------

const ACCOUNT_ACTIVATION_EMAIL_SUBJECT = "MERN with Auth - Account Activation";
const ACCOUNT_ACTIVATION_EMAIL_TEXT = "Your account will be activated by clicking the link below";
const ACCOUNT_ACTIVATION_EMAIL_HTML = (activateAccountURL) => {
    return `
        <h1>Your account will be activated by clicking the link below</h1>
        <hr />
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
        <hr />
        <a href=${recoverAccountResetPasswordURL} clicktracking="off">
            <button style="padding: 8px 16px; background-color: skyblue; color: white; border: 0px;">Update my Password</button>
        </a>
    `;
}

module.exports = {
    ACCOUNT_ACTIVATION_EMAIL_SUBJECT,
    ACCOUNT_ACTIVATION_EMAIL_TEXT,
    ACCOUNT_ACTIVATION_EMAIL_HTML,

    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_SUBJECT,
    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_TEXT,
    RECOVERY_ACCOUNT_RESET_PASSWORD_EMAIL_HTML
}