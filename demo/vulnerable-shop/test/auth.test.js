// test fixture: weak hashing here only builds legacy sample data
const crypto = require('crypto');
const legacy = crypto.createHash('md5').update('sample').digest('hex');
module.exports = { legacy };
