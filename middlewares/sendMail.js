// utils/email.js
const nodemailer = require('nodemailer');
const { htmlToText } = require('html-to-text'); // For converting HTML to plain text

module.exports = class Email {
    constructor(user, data) { // 'data' can be a token or a code
        this.to = user.email;
        this.firstName = user.email.split('@')[0]; // Using email prefix if no name field
        this.data = data; // This will hold the code or token
        this.from = process.env.EMAIL_FROM;
    }

    newTransport() {
        return nodemailer.createTransport({
            host: process.env.EMAIL_HOST,
            port: process.env.EMAIL_PORT,
            secure: process.env.EMAIL_PORT == 465, // Use true for port 465 (SSL), false for other ports (TLS)
            auth: {
                user: process.env.EMAIL_USERNAME,
                pass: process.env.EMAIL_PASSWORD
            }
        });
    }

    async send(subject, htmlContent) {
        // Define email options
        const mailOptions = {
            from: this.from,
            to: this.to,
            subject,
            html: htmlContent,
            text: htmlToText(htmlContent) // Convert HTML to plain text
        };

        // Create a transport and send email
        try {
            await this.newTransport().sendMail(mailOptions);
            return { accepted: [this.to] }; // Mimic nodemailer's success response
        } catch (error) {
            console.error('Error sending email:', error);
            return { accepted: [] }; // Indicate failure
        }
    }

    async sendWelcome() {
        const html = `
            <p>Hi ${this.firstName},</p>
            <p>Welcome to our application! We're excited to have you on board.</p>
            <p>Thank you for signing up.</p>
            <p>The App Team</p>
        `;
        await this.send('Welcome to the App!', html);
    }

    async sendVerificationCode() {
        const html = `
            <p>Hi ${this.firstName},</p>
            <p>Your verification code is: <strong>${this.data}</strong></p>
            <p>This code is valid for 5 minutes. If you did not request this, please ignore this email.</p>
            <p>The App Team</p>
        `;
        await this.send('Your Verification Code', html);
    }

    async sendForgotPasswordCode() {
        const html = `
            <p>Hi ${this.firstName},</p>
            <p>You have requested to reset your password. Your password reset code is: <strong>${this.data}</strong></p>
            <p>This code is valid for 5 minutes. If you did not request this, please ignore this email.</p>
            <p>The App Team</p>
        `;
        await this.send('Your Forgot Password Code', html);
    }
};
