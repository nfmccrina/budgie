var mongoose = require('mongoose');
var User = require('../data/models/user');
var userSchema = require('../data/schemas/user');
var log4js = require('log4js');
var util = require('util');
var bcrypt = require('bcrypt');
var moment = require('moment');
var jwt = require('jsonwebtoken');

const saltRounds = 10;

function UserService () {
    this.logger = log4js.getLogger('debugLog');
};

UserService.prototype.userExists = function (id) {
    return User.count({ budgieId: id})
        .then((count) => {
            console.log(count);
            return count > 0
        });
};

UserService.prototype.getUser = function (name, id) {
    return this.userExists(id)
        .then((exists) => {
            if (!exists) {
                return Promise.resolve(new User({
                    name: name,
                    budgieId: id
                }))
                .then((u) => u.save())
                .then((createdUser) => {
                    this.logger.debug('added user ' + util.inspect(createdUser));
                    return {
                        budgieId: createdUser.budgieId,
                        name: createdUser.name
                    }
                });
            } else {
                return User.findOne({ budgieId: id })
                    .then((user) => {
                        return {
                            budgieId: user.budgieId,
                            name: user.name
                        }
                    });
            }
        });
};

module.exports = UserService;