const nodemailer = require("nodemailer");


const transport = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user,
        pass
    }
})