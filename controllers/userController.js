var UserService = require('../services/userService');
var log4js = require('log4js');
var bcrypt = require('bcrypt');
var util = require('util');

const saltRounds = 10;

function UserController () {
    this.logger = log4js.getLogger('debugLog');
    this.userService = new UserService();
}

UserController.prototype.getUsers = function () {  
    return this.userService
        .getAll()
        .then((users) => {
            this.logger.debug('UserController.getUsers called');
            return users;
        })
        .catch((err) => {
            this.logger.debug('UserController.getUsers - ' + err.toString());
            return [];
        });
};

UserController.prototype.addUser = function (req, res) {
    this.logger.debug('UserController.addUser invoked');

    if (!req.body || !req.body.name || !req.body.pwd) {
        this.logger.debug('invalid data: req.body = ' + util.inspect(req.body));
        res.status(400).send('Bad Request');
    }

    bcrypt.hash(req.body.pwd, saltRounds)
        .then((hash) => this.userService.addUser(req.body.name, hash))
        .then((createdUser) => res.json(createdUser))
        .catch((err) => {
            this.logger.debug('error: ' + util.inspect(err));
            res.status('500').send('Server Error');
        });
};

module.exports = UserController;