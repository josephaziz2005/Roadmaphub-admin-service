// Password rules (checked on the server; the browser only repeats them as hints).
const COMMON = new Set(['password123', 'qwerty12345', '1234567890', 'iloveyou123', 'password1234', 'letmein12345', 'welcome12345', 'admin123456']);

function checkPassword(password, email) {
  if (typeof password !== 'string' || password.length < 10 || password.length > 128) {
    return 'password must contain between 10 and 128 characters.';
  }
  if (!/[A-Za-z]/.test(password) || !/[0-9]/.test(password)) {
    return 'password must contain at least one letter and one number.';
  }
  const localPart = (email || '').split('@')[0].toLowerCase();
  if (localPart.length >= 3 && password.toLowerCase().includes(localPart)) {
    return 'password must not contain your e-mail name.';
  }
  if (COMMON.has(password.toLowerCase())) return 'password is too common.';
  return null;
}

module.exports = { checkPassword };
