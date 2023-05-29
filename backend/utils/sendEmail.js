const nodemailer = require("nodemailer");

const sendEmail = async ({ to, subject, text, html }) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    secure: process.env.NODE_ENV == "PRODUCTION" ? true : false,
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  const emailOptions = {
    from: `MERN <${process.env.EMAIL_FROM}>`,
    to,
    subject,
    text,
    html,
  };

  // Sending email activation account
  transporter.sendMail(emailOptions, (error, info) => {
    if (error) {
      console.log({
        fileName: 'sendEmail.js',
        errorDescription: 'There is something problem on the sending the activation link to the user via email.',
        errorLocation: 'sendEmailActivationAccount',
        error: error
      });
    }
  });
};

module.exports = sendEmail;