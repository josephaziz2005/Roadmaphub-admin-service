// Chooses the database adapter (STORAGE_DRIVER). Business logic only talks to these
// repository functions, never to the AWS SDK directly.
const { storage } = require('../shared');

module.exports = storage.chooseDriver('admin-service', {
  dynamodb: () => require('./dynamodb')
});
