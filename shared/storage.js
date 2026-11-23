// STORAGE_DRIVER chooses the database adapter explicitly (no silent fallback):
//   dynamodb (default, Floci)    postgres (Neon, supplementary Vercel deployment)
function chooseDriver(serviceName, adapters) {
  const driver = (process.env.STORAGE_DRIVER || 'dynamodb').trim();
  const factory = adapters[driver];
  if (!factory) {
    throw new Error(`${serviceName}: STORAGE_DRIVER=${driver} is not available (choose: ${Object.keys(adapters).join(', ')})`);
  }
  return factory();
}

module.exports = { chooseDriver };
