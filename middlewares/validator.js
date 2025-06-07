const Joi = require("joi");
// This schema is used to vaildate request body and make sure them meet the stated criteria

exports.signupSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds: {allow: ['com', 'net']}
        }),
    password: Joi.string()
        .required()
        .pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)),
});


exports.loginSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds: {allow: ['com', 'net']}
        }),
    password: Joi.string()
        .required()
        .pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/))
})


exports.acceptCodeSchema = Joi.object({
    email: Joi.string()
        .min(6)
        .max(60)
        .required()
        .email({
            tlds: {allow: ['com', 'net']}
        }),
        providedCode: Joi.string().required()
});


exports.changePassswordSchema = Joi.object({
    newPassword: Joi.string()
        .required()
        .pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/)),
    oldPassword: Joi.string()
        .required()
        .pattern(new RegExp(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/))
})