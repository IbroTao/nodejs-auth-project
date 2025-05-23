const transport = require("../middlewares/sendMail.js");
const { signupSchema, loginSchema } = require("../middlewares/validator.js"); // This is imported to ensure the req. body meets certain criteria
const User = require("../models/usersModel.js");
const { hashPassword, hashPasswordValidation, hmacProcess } = require("../utilis/hash.js");
const jwt = require("jsonwebtoken");

exports.signup = async (req, res) => {
    const { email, password } = req.body;
    try {
        const { error } = signupSchema.validate({ email, password }); // This is imported to ensure the req. body meets certain criteria

        if (error) {
            return res.status(401).json({ success: false, message: error.details[0] });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(401).json({ success: false, message: "User already exists!" });
        }

        const passwordHashed = await hashPassword(password, 12);

        const newUser = new User({
            email,
            password: passwordHashed
        });

        const result = await newUser.save();
        result.password = undefined;

        res.status(201).json({
            success: true,
            message: "Your account has been created!",
            result
        });
    } catch (error) {
        console.error("Signup error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
};

exports.login = async (req, res) => {
    const { email, password } = req.body;
    try {
        console.log("Login attempt:", email);

        const { error } = loginSchema.validate({ email, password });
        if (error) {
            console.log("Validation error:", error.details[0]);
            return res.status(401).json({ success: false, message: error.details[0] });
        }

        const exisitingUser = await User.findOne({ email }).select('+password');
        if (!exisitingUser) {
            res.status(404).json({ success: false, message: "User does not exist!" });
        }

        const result = await hashPasswordValidation(password, exisitingUser.password);
        if (!result) {
            console.log("Invalid password");
            return res.status(401).json({ success: false, message: "Invalid credentials!" });
        }

        const token = jwt.sign({
            userId: exisitingUser._id,
            email: exisitingUser.email,
            verified: exisitingUser.verified
        }, process.env.JWT_SECRET);

        res.cookie('Authorization', `Bearer ${token}`, {
            expires: new Date(Date.now() + 8 * 3600000),
            httpOnly: process.env.NODE_ENV === 'production',
            secure: process.env.NODE_ENV === 'production'
        });

        console.log("Login successful");
        return res.status(200).json({
            success: true,
            token,
            message: "Login successfully"
        });

    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}

exports.logout = async(req, res) => {
    res.clearCookie('Authorization').status(200).json({sucess: true, message: "Logged out!"})
}

exports.sendVerificationCode = async (req, res) => {
    const { email } = req.body;
    try {
        const existingUser = await User.findOne({ email });
        if (!existingUser) {
            return res.status(404).json({ success: false, message: "User does not exist!" });
        }

        if (existingUser.verified) {
            return res.json({ success: false, message: "You are already verified!" });
        }

        const codeValue = Math.floor(Math.random() * 1000000).toString().padStart(6, '0');

        let info = await transport.sendMail({
            from: process.env.CODE_SENDING_EMAIL_ADDRESS,
            to: existingUser.email,
            subject: "Verification Code",
            html: '<h1>' + codeValue + '</h1>'
        });

        if (info.accepted && info.accepted[0] === existingUser.email) {
            const hashedCodeValue = hmacProcess(codeValue, process.env.HMAC_VERIFICATION_CODE_SECRET);
            existingUser.verificationCode = hashedCodeValue;
            existingUser.verificationCodeValidation = Date.now();
            await existingUser.save();
            return res.status(200).json({ success: true, message: "Verification code sent!" });
        }

        res.status(400).json({ success: false, message: "Code send failed!" });

    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: "Server error!" });
    }
}

exports.verifyVerificationCode = async(req, res) => {
    const {email, providedCode} = req.body;
    try {
        
    } catch (error) {
        
    }
}