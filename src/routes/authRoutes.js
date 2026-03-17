const express = require('express');
const router = express.Router();
const auth = require('../controllers/authController');
const { authenticate } = require('../middleware/auth');
const {
  registerRules,
  loginRules,
  changePasswordRules,
  resetPasswordRules,
  forgotPasswordRules,
} = require('../middleware/validate');

// Public routes
router.post('/register', registerRules, auth.register);
router.post('/login', loginRules, auth.login);
router.post('/refresh-token', auth.refreshToken);
router.post('/forgot-password', forgotPasswordRules, auth.forgotPassword);
router.post('/reset-password/:token', resetPasswordRules, auth.resetPassword);

// Protected routes
router.post('/logout', authenticate, auth.logout);
router.get('/me', authenticate, auth.getMe);
router.patch('/update-profile', authenticate, auth.updateProfile);
router.patch('/change-password', authenticate, changePasswordRules, auth.changePassword);
router.delete('/delete-account', authenticate, auth.deleteAccount);

module.exports = router;
