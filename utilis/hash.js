// utils/hash.js
const bcrypt = require('bcryptjs');
const crypto = require('crypto'); // Built-in Node.js module

// Hashes a password using bcrypt
exports.hashPassword = async (password, saltRounds) => {
    return await bcrypt.hash(password, saltRounds);
};

// Validates a plain password against a hashed password
exports.hashPasswordValidation = async (plainPassword, hashedPassword) => {
    return await bcrypt.compare(plainPassword, hashedPassword);
};

// Creates an HMAC hash for sensitive data like verification codes
exports.hmacProcess = (data, secret) => {
    return crypto.createHmac('sha256', secret)
                .update(data)
                .digest('hex');
};
