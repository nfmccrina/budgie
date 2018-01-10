var mongoose = require('mongoose');
var ObjectId = mongoose.Schema.Types.ObjectId;

exports = module.exports = mongoose.Schema({
    name: String,
    saltedHashedPassword: String,
    token: String,
    tokenExpiration: Date
});