const { hash, compare } = require("bcryptjs")

exports.hashPassword = (value, saltValue) => {
    const result = hash(value, saltValue);
    return result;
}

exports.hashPasswordValidation = (value, hashedValue) => {
    const result = compare(value, hashedValue);
    return result;
}

// exports.hmacProcess = (value, key) => {
//     const result = createHmac('sha256', key).update(value).digest('hex');
//     return result;
// }