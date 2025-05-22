const nodemailer = require("nodemailer");


const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.CODE_SENDING_EMAIL_ADDRESS,
        pass: process.env.APP_PASSWORD
    }
});


module.exports = transport;