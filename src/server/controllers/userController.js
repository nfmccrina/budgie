var UserService = require('../services/userService');
var log4js = require('log4js');
var bcrypt = require('bcrypt');
var util = require('util');

const saltRounds = 10;

function UserController () {
    this.logger = log4js.getLogger('debugLog');
    this.userService = new UserService();
}

UserController.prototype.getUser = function (req, res) {
    this.logger.debug('UserController.addUser invoked');

    if (!req.user || ! req.user.sub || !req.user['https://budgie.com/name']) {
        this.logger.debug('bad request: ' + util.inspect(req));
        res.status(400).end();
    }
    
    this.userService.getUser(this.parseUserName(req.user['https://budgie.com/name']), this.parseUserId(req.user.sub))
        .then((createdUser) => res.json(createdUser))
        .catch((err) => {
            this.logger.debug('error: ' + util.inspect(err));
            res.status('500').end();
        });
};

UserController.prototype.addCategory = function (req, res) {
    this.logger.debug('UserController.addCategory invoked');

    if (!req.user || ! req.user.sub || !req.user['https://budgie.com/name']) {
        this.logger.debug('bad request: ' + util.inspect(req));
        res.status(400).end();
    }

    return this.userService.addCategory(this.parseUserId(req.user.sub), req.body.category.name)
        .then((obj) => res.json(obj))
        .catch((err) => {
            this.logger.debug('error: ' + util.inspect(err));
            return res.status('500').end();
        })
};

UserController.prototype.parseUserName = function (str) {
    return str.split('@')[0];
};

UserController.prototype.parseUserId = function (str) {
    var parts = str.split('|');

    if (parts.length > 1) {
        return parts[1];
    } else {
        return parts[0];
    }
};

module.exports = UserController;