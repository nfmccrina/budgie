var mongoose = require('mongoose');
var User = require('../data/models/user');
var log4js = require('log4js');

function UserService () {};

UserService.prototype.addUser = function (name, pwd) {
    var newUser = new User({
        name: name,
        saltedHashedPassword: pwd,
        token: '',
        tokenExpiration: new Date('1900-01-01')
    });
    
    return newUser.save();
};

UserService.prototype.getAll = function () {
    var logger = log4js.getLogger('debugLog');
    
    return User
        .find()
        .exec()
        .then((users) => {
            logger.debug('UserService.getAll returned ' + (users && users.length ? users.length : 0) + ' users');
            return users;
        })
        .then((users) => users.map((u) => {
            return {
                id: u._id,
                name: u.name
            };
        }))
        .catch((err) => {
            logger.debug('UserService.getAll - ' + err.toString());
            return [];
        });
};

module.exports = UserService;