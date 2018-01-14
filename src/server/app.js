require('dotenv').config();
var mongoose = require('mongoose');
var express = require('express');
var app = express();
var apiRouter = require('./routing/apiRoutes');
var log4js = require('log4js');
log4js.configure('./log.config');

function App () {}

App.prototype.buildConnectionURL = function () {
    var logger = log4js.getLogger('debugLog');
    
    var result = 'mongodb://' + process.env.MONGODB_USERNAME + ':' + process.env.MONGODB_PASSWORD + '@' + process.env.MONGODB_HOST + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DATABASE;
    logger.debug('mongodb connection URL is "' + result + '"');
    return result;
};

App.prototype.start = function () {
    mongoose.connect(this.buildConnectionURL(), {})
        .then((conn) => app.use('/api', apiRouter))
        .then(() => app.use(express.static('wwwroot')))
        .then(() => app.listen(3000))
        .then(() => console.log('Listening on port 3000...'));
};

module.exports = App;