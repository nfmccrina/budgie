var mongoose = require('mongoose');
var userSchema = require('../schemas/user');

exports = module.exports = mongoose.model('User', userSchema);