const express = require("express");
const authController = require("../controllers/authController.js")
const router = express.Router();


router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/logout', authController.logout);

router.patch('/send-verification-code', authController.sendVerificationCode);

module.exports = router;