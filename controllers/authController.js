// HTTP layer for login and registration: validates the request, calls authService, picks the status code.
const { validate: v } = require('../shared');
const authService = require('../services/authService');

async function register(req, res) {
  v.onlyFields(req.body, ['name', 'email', 'password']); // "role" in the body -> 400 (no self-made admins)
  const name = v.text(req.body, 'name', { min: 2, max: 60 });
  const email = v.email(req.body);
  const { password } = req.body;
  const result = await authService.register({ name, email, password, ip: req.ip, requestId: req.id });
  res.status(201).json(result);
}

async function login(req, res) {
  v.onlyFields(req.body, ['email', 'password']);
  const email = v.email(req.body);
  const password = v.text(req.body, 'password', { min: 1, max: 128 });
  res.status(200).json(await authService.login({ email, password, ip: req.ip, requestId: req.id }));
}

async function me(req, res) {
  res.status(200).json({ user: await authService.me(req.user.id) });
}

async function logout(req, res) {
  await authService.logout(req.user.id, req.ip, req.id);
  res.status(204).end();
}

module.exports = { register, login, me, logout };
