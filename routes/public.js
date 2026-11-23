// Public routes of the Administration Service (mounted at /api).
const express = require('express');
const { rateLimit, turnstile } = require('../shared');
const auth = require('../middleware/auth');
const authController = require('../controllers/authController');
const admin = require('../controllers/adminController');

const router = express.Router();
const registerLimiter = rateLimit.createRateLimiter({ name: 'register', windowMs: 10 * 60000, max: 5 });
const loginLimiter = rateLimit.createRateLimiter({ name: 'login', windowMs: 60000, max: 10 });
const adminLimiter = rateLimit.createRateLimiter({ name: 'admin', windowMs: 60000, max: 120, key: 'user' });

// Identity (this service is the only one that creates accounts and issues logins)
router.post('/auth/register', registerLimiter, turnstile.requireTurnstile, authController.register);
router.post('/auth/login', loginLimiter, authController.login);
router.get('/auth/me', auth.requireUser, authController.me);
router.post('/auth/logout', auth.requireSession, authController.logout);

// Administration: every route below needs a logged-in admin (checked here, in the backend)
router.use('/admin', auth.requireUser, auth.requireRole('admin'), adminLimiter);
router.get('/admin/features/:id/duplicate-suggestions', admin.duplicateSuggestions);
router.post('/admin/features/:id/merge', admin.merge);
router.get('/admin/merges', admin.listMerges);
router.post('/admin/merges/:mergeId/undo', admin.undo);
router.get('/admin/users', admin.listUsers);
router.patch('/admin/users/:id/status', admin.changeUserStatus);
router.get('/admin/audit', admin.auditLog);
router.get('/admin/security-events', admin.securityEvents);

module.exports = router;
