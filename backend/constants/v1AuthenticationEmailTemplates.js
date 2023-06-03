const accountActivationEmailTemplate = (activateAccountURL) => {
    return `
        <h1>Your account will be activated by clicking the link below</h1>
        <hr />
        <a href=${activateAccountURL} clicktracking=off>
            <button style="padding: 8px 16px; background-color: skyblue; color: white;">Activate my Account</button>
        </a>
    `
}

const recoverAccountResetPasswordEmailTemplate = (recoverAccountResetPasswordURL) => {
    return `
        <h1>You can update your password to recover your account by clicking the link below</h1>
        <hr />
        <a href=${recoverAccountResetPasswordURL} clicktracking=off>
            <button style="padding: 8px 16px; background-color: skyblue; color: white;">Update my Password</button>
        </a>
    `
}

module.exports = {
    accountActivationEmailTemplate,
    recoverAccountResetPasswordEmailTemplate
}