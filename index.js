require('dotenv').config();
var log4js = require('log4js');
var mongoose = require('mongoose');
var UserController = require('./controllers/userController');

log4js.configure('log.config');

function runApp () {
    var userController = new UserController();
    userController.getUsers();
}

function buildConnectionURL () {
    var logger = log4js.getLogger('debugLog');
    
    var result = 'mongodb://' + process.env.MONGODB_HOST + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DATABASE;
    
    logger.debug('mongodb connection URL is "' + result + '"');
    //return 'mongodb://' + process.env.MONGODB_USERNAME + ':' + process.env.MONGODB_PASSWORD + '@' + process.env.MONGODB_HOST + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DATABASE;
    return result;
}

mongoose.connect(buildConnectionURL(), {})
    .then((conn) => runApp())
    .catch((err) => {
        var logger = log4js.getLogger('debugLog');
        
        logger.debug('mongoose.connect - ' + err.toString());
    });