// controllers/authController.js
const jwt = require('jsonwebtoken');
const User = require('../models/usersModel.js');
const AppError = require('../utils/ApiError.js');
const catchAsync = require('../utils/catchAsync.js');
const Email = require('../utils/email.js'); // Updated to use the Email class
const { hashPassword, hashPasswordValidation, hmacProcess } = require("../utils/hash.js"); // Corrected path to utils
const { signupSchema, loginSchema, acceptCodeSchema, changePassswordSchema, acceptForgotPasswordSchema } = require("../middlewares/validator.js");


// Helper to create and send JWT token
const signToken = id => {
    return jwt.sign({ userId: id }, process.env.JWT_SECRET, { // Using userId to match decoded token in middleware
        expiresIn: process.env.JWT_EXPIRES_IN
    });
};

const createSendToken = (user, statusCode, res) => {
    const token = signToken(user._id);

    // Set cookie options
    const cookieOptions = {
        expires: new Date(
            Date.now() + process.env.JWT_COOKIE_EXPIRES_IN * 24 * 60 * 60 * 1000 // Convert days to milliseconds
        ),
        httpOnly: true, // Prevents client-side JS from reading the cookie
        secure: process.env.NODE_ENV === 'production' // Send only on HTTPS in production
    };

    res.cookie('Authorization', `Bearer ${token}`, cookieOptions); // Store token in a cookie

    // Remove sensitive fields from output
    user.password = undefined;
    user.verificationCode = undefined;
    user.verificationCodeValidation = undefined;
    user.forgotPasswordCode = undefined;
    user.forgotPasswordCodeValidation = undefined;

    res.status(statusCode).json({
        success: true,
        token,
        data: {
            user
        }
    });
};

// User Signup
exports.signup = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    const { error } = signupSchema.validate({ email, password });

    if (error) {
        return next(new AppError(error.details[0].message, 400));
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
        return next(new AppError("User already exists!", 409)); // 409 Conflict for existing resource
    }

    // Password hashing handled by pre-save hook in user model
    const newUser = await User.create({
        email,
        password
    });

    // Send welcome email
    try {
        await new Email(newUser).sendWelcome();
    } catch (emailErr) {
        console.error('Error sending welcome email:', emailErr);
        // Do not block user creation, but log the error
    }

    createSendToken(newUser, 201, res);
});

// User Login
exports.login = catchAsync(async (req, res, next) => {
    const { email, password } = req.body;
    const { error } = loginSchema.validate({ email, password });

    if (error) {
        return next(new AppError(error.details[0].message, 400));
    }

    // 1) Check if email and password exist
    if (!email || !password) {
        return next(new AppError('Please provide email and password!', 400));
    }

    // 2) Check if user exists AND password is correct
    const user = await User.findOne({ email }).select('+password'); // Select password for comparison

    if (!user || !(await hashPasswordValidation(password, user.password))) { // Use your hashPasswordValidation
        return next(new AppError('Incorrect email or password', 401));
    }

    // 3) If everything is ok, send token to client
    createSendToken(user, 200, res);
});

// User Logout
exports.logout = (req, res) => {
    res.clearCookie('Authorization', {
        expires: new Date(Date.now() + 10 * 1000), // Expire immediately
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production'
    }).status(200).json({ success: true, message: "Logged out successfully!" });
};

// Send Verification Code (e.g., for email verification after signup)
exports.sendVerificationCode = catchAsync(async (req, res, next) => {
    const { email } = req.body;

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
        return next(new AppError("User does not exist!", 404));
    }

    if (existingUser.verified) {
        return next(new AppError("You are already verified!", 400));
    }

    const codeValue = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

    const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

    existingUser.verificationCode = hashedCodeValue;
    existingUser.verificationCodeValidation = Date.now(); // Set current time
    await existingUser.save({ validateBeforeSave: false }); // Save without running full validation

    try {
        const info = await new Email(existingUser, codeValue).sendVerificationCode();
        if (info.accepted && info.accepted[0] === existingUser.email) {
            return res.status(200).json({ success: true, message: "Verification code sent!" });
        }
        return next(new AppError("Failed to send verification code email.", 500));
    } catch (error) {
        console.error('Error sending verification code email:', error);
        return next(new AppError("There was an error sending the verification code. Try again later!", 500));
    }
});

// Verify Verification Code
exports.verifyVerificationCode = catchAsync(async (req, res, next) => {
    const { email, providedCode } = req.body;
    const { error } = acceptCodeSchema.validate({ email, providedCode });

    if (error) {
        return next(new AppError(error.details[0].message, 400));
    }

    const existingUser = await User.findOne({ email }).select("+verificationCode +verificationCodeValidation +verified");
    if (!existingUser) {
        return next(new AppError("User does not exist!", 404));
    }

    if (existingUser.verified) {
        return next(new AppError("You are already verified!", 400));
    }

    if (!existingUser.verificationCode || !existingUser.verificationCodeValidation) {
        return next(new AppError("No verification code found or something is wrong.", 400));
    }

    // Check if code is expired (5 minutes)
    if (Date.now() - existingUser.verificationCodeValidation > 5 * 60 * 1000) {
        return next(new AppError("The code has expired, please request a new one!", 400));
    }

    const hashedProvidedCode = hmacProcess(providedCode, process.env.HMAC_VERIFICATION_CODE_SECRET);

    if (hashedProvidedCode === existingUser.verificationCode) {
        existingUser.verified = true;
        existingUser.verificationCode = undefined;
        existingUser.verificationCodeValidation = undefined;
        await existingUser.save({ validateBeforeSave: false }); // Save without running full validation
        return res.status(200).json({ success: true, message: "Your account has been verified!" });
    }

    return next(new AppError("Invalid verification code!", 400));
});


// Change Password (for authenticated users)
exports.changePassword = catchAsync(async (req, res, next) => {
    const { _id, verified } = req.user; // req.user populated by protect middleware
    const { oldPassword, newPassword } = req.body;
    const { error } = changePassswordSchema.validate({ oldPassword, newPassword });

    if (error) {
        return next(new AppError(error.details[0].message, 400));
    }

    if (!verified) {
        return next(new AppError("You are not verified!", 403)); // 403 Forbidden
    }

    const user = await User.findById(_id).select('+password'); // Select password for comparison
    if (!user) {
        return next(new AppError("User does not exist!", 404));
    }

    // Check if old password is correct
    if (!(await hashPasswordValidation(oldPassword, user.password))) {
        return next(new AppError('Your current password is wrong.', 401));
    }

    // Set the new password (pre-save hook will hash it)
    user.password = newPassword;
    await user.save(); // Mongoose pre-save hook will hash it and update passwordChangedAt

    // Log user in, send new JWT (optional, but good for security)
    createSendToken(user, 200, res);
});


// Send Forgot Password Code
exports.sendForgotPasswordCode = catchAsync(async (req, res, next) => {
    const { email } = req.body;

    const existingUser = await User.findOne({ email });
    if (!existingUser) {
        return next(new AppError("User does not exist!", 404));
    }

    // Only send if the user is verified to prevent abuse
    if (!existingUser.verified) {
        return next(new AppError("Only verified users can reset password. Please verify your email first.", 403));
    }

    const codeValue = Math.floor(100000 + Math.random() * 900000).toString(); // 6-digit code

    const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);

    existingUser.forgotPasswordCode = hashedCodeValue;
    existingUser.forgotPasswordCodeValidation = Date.now(); // Set current time
    await existingUser.save({ validateBeforeSave: false });

    try {
        const info = await new Email(existingUser, codeValue).sendForgotPasswordCode();
        if (info.accepted && info.accepted[0] === existingUser.email) {
            return res.status(200).json({ success: true, message: "Forgot password code sent to email!" });
        }
        return next(new AppError("Failed to send forgot password email.", 500));
    } catch (error) {
        console.error('Error sending forgot password email:', error);
        return next(new AppError("There was an error sending the forgot password code. Try again later!", 500));
    }
});


// Verify Forgot Password Code and Reset Password
exports.verifyForgotPassswordCode = catchAsync(async (req, res, next) => {
    const { email, providedCode, newPassword } = req.body;
    const { error } = acceptForgotPasswordSchema.validate({ email, providedCode, newPassword });

    if (error) {
        return next(new AppError(error.details[0].message, 400));
    }

    const existingUser = await User.findOne({ email }).select("+forgotPasswordCode +forgotPasswordCodeValidation +verified");
    if (!existingUser) {
        return next(new AppError("User does not exist!", 404));
    }

    // Optional: You might still want to check if verified for consistency, or rely on sendForgotPasswordCode's check
    if (!existingUser.verified) {
        return next(new AppError("Only verified users can reset password. Please verify your email first.", 403));
    }

    if (!existingUser.forgotPasswordCode || !existingUser.forgotPasswordCodeValidation) {
        return next(new AppError("No forgot password code found or something is wrong.", 400));
    }

    // Check if code is expired (5 minutes)
    if (Date.now() - existingUser.forgotPasswordCodeValidation > 5 * 60 * 1000) {
        return next(new AppError("The code has expired, please request a new one!", 400));
    }

    const hashedProvidedCode = hmacProcess(providedCode, process.env.HMAC_VERIFICATION_CODE_SECRET);

    if (hashedProvidedCode === existingUser.forgotPasswordCode) {
        // Hash the new password (pre-save hook will handle it)
        existingUser.password = newPassword;
        existingUser.forgotPasswordCode = undefined;
        existingUser.forgotPasswordCodeValidation = undefined;
        await existingUser.save(); // Password hashing and passwordChangedAt update will occur here

        // Log user in, send JWT
        createSendToken(existingUser, 200, res);
    } else {
        return next(new AppError("Invalid forgot password code!", 400));
    }
});
