const express = require("express");
const authController = require("../controllers/authController.js")
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
router.post('/logout', authController.logout);

router.patch('/send-verification-code', authController.sendVerificationCode);
router.patch('/verify-verification-code', authController.verifyVerificationCode);
router.patch('/change-password', authController.changePassword);



module.exports = router;