var mongoose = require('mongoose');
var Category = require('./category');

exports = module.exports = mongoose.Schema({
    name: String,
    budgieId: String,
    categories: [Category]
});