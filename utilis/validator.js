// middlewares/validator.js
const Joi = require('joi');

// Schema for user signup
exports.signupSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(8).required() // Minimum 8 characters for password
});

// Schema for user login
exports.loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().required()
});

// Schema for accepting verification code
exports.acceptCodeSchema = Joi.object({
    email: Joi.string().email().required(),
    providedCode: Joi.string().length(6).pattern(/^[0-9]+$/).required() // 6-digit number
});

// Schema for changing password (when logged in)
exports.changePassswordSchema = Joi.object({
    oldPassword: Joi.string().required(),
    newPassword: Joi.string().min(8).required()
});

// Schema for accepting forgot password code and setting new password
exports.acceptForgotPasswordSchema = Joi.object({
    email: Joi.string().email().required(),
    providedCode: Joi.string().length(6).pattern(/^[0-9]+$/).required(),
    newPassword: Joi.string().min(8).required()
});
