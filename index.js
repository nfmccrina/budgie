require('dotenv').config();
var log4js = require('log4js');
var mongoose = require('mongoose');
var express = require('express');
var app = express();
var apiRouter = require('./config/routing/apiRoutes');

log4js.configure('log.config');

var logger = log4js.getLogger('debugLog');

app.use('/api', apiRouter);

function buildConnectionURL () {
    var logger = log4js.getLogger('debugLog');
    
    var result = 'mongodb://' + process.env.MONGODB_USERNAME + ':' + process.env.MONGODB_PASSWORD + '@' + process.env.MONGODB_HOST + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DATABASE;
    logger.debug('mongodb connection URL is "' + result + '"');
    return result;
}

function runApp () {
    mongoose.connect(buildConnectionURL(), {})
        .then((conn) => app.listen(3000))
        .then(() => console.log('Listening on port 3000...'));
}

runApp();