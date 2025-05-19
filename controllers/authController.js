const { signupSchema, loginSchema } = require("../middlewares/validator.js"); // This is imported to ensure the req. body meets certain criteria
const User = require("../models/usersModel.js");
const { hashPassword } = require("../utilis/hash.js");

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

exports.login = async(req, res) => {
    const {email, password} = req.body;
    try {
        const {error} = loginSchema.validate({email, password});
        if(error) {
            return res.status(401).json({success: false, message: error.details[0]})
        }

        const exisitingUser = await User.findOne({email}).select('+password');
        if(!existingUser) {
            return res.status(401).json({success: false, message: "User does not exist!"})
        }
    } catch (error) {
        console.error("Login error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
}
