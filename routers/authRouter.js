const express = require("express");
const authController = require("../controllers/authController.js");
const { identifier } = require("../middlewares/authorize.js");
const router = express.Router();

/**
 * @swagger
 * /api/auth/signup:
 *   post:
 *     summary: Register a new user
 *     tags: [Authentication]
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/SignupRequest'
 *     responses:
 *       201:
 *         description: User account created successfully.
 *       401:
 *         description: Validation error or user already exists.
 *       500:
 *         description: Internal server error.
 */
router.post('/signup', authController.signup);
router.post('/login', authController.login);
router.post('/logout', identifier, authController.logout);

router.patch('/send-verification-code', identifier, authController.sendVerificationCode);
router.patch('/verify-verification-code', identifier, authController.verifyVerificationCode);
router.patch('/change-password', identifier, authController.changePassword);
router.patch('/send-forgot-password-code', identifier, authController.sendForgotPasswordCode);
router.patch('/verify-forgot-password-code', identifier, authController.verifyForgotPassswordCode);





module.exports = router;