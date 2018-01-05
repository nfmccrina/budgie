var UserService = require('../services/userService');
var log4js = require('log4js');
function UserController () {}

UserController.prototype.getUsers = function () {
    var userService = new UserService();
    var logger = log4js.getLogger('debugLog');
    
    return userService
        .getAll()
        .then((users) => {
            logger.debug('UserController.getUsers called');
            return users;
        })
        .catch((err) => {
            logger.debug('UserController.getUsers - ' + err.toString());
            return [];
        });
};

module.exports = UserController;