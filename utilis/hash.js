const { hash, compare } = require("bcryptjs")

exports.hashPassword = (value, saltValue) => {
    const result = hash(value, saltValue);
    return result;
}

exports.hashPasswordValidation = (value, hashedValue) => {
    const result = compare(value, hashedValue);
    return result;
}