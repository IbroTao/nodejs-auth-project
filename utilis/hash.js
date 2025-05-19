const { hash } = require("bcryptjs")

exports.hashPassword = (value, saltValue) => {
    const result = hash(value, saltValue);
    return result;
}