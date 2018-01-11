var mongoose = require('mongoose');
var User = require('../data/models/user');
var userSchema = require('../data/schemas/user');
var log4js = require('log4js');
var util = require('util');
var bcrypt = require('bcrypt');
var tokenGenerator = require('uuid/v4');
var moment = require('moment');

const saltRounds = 10;

function UserService () {
    this.logger = log4js.getLogger('debugLog');
};

UserService.prototype.addUser = function (name, pwd) {
    return bcrypt.hash(pwd, saltRounds)
        .then((hash) => {
            var newUser = new User({
                name: name,
                saltedHashedPassword: hash,
                token: '',
                tokenExpiration: new Date('1900-01-01')
            });

            return newUser.save();
        })
        .then((createdUser) => {
            return {
                id: createdUser._id,
                name: createdUser.name
            }
        });
};

UserService.prototype.loginUser = function (userName, pwd) {
    var user = mongoose.model('User', userSchema);

    // get the user
    var userPromise = User.findOne({ name: userName}).exec();

    // check password
    var isValidPromise = userPromise.then((user) => user.saltedHashedPassword)
        .then((hash) => bcrypt.compare(pwd, hash));

    // update/create token if password is valid. If not valid throw.
    var createTokenPromise = isValidPromise.then((isValid) => {
        if (isValid) {
            return this.generateToken(userName);
        } else {
            throw 'invalid login';
        }
    });

    return Promise.all([userPromise, isValidPromise, createTokenPromise])
        .then((result) => {
            // if password is valid return User with updated token and expiration otherwise throw
            if (result[1]) {
                return {
                    id: result[2]._id,
                    token: result[2].token
                }
            } else {
                throw 'invalid login';
            }
        })
        .catch((err) => {
            // return a user with no token (login fails)
            this.logger.debug('loginUser: error - ' + util.inspect(err));
            return User.findOneAndUpdate({
                name: userName
            }, {
                token: '',
                tokenExpiration: new Date('1900-01-01')
            }, {
                new: true
            }).exec()
            .then((u) => {
                return {
                    id: u._id,
                    token: u.token
                }
            });
        });
};

UserService.prototype.isUserTokenValid = function (userId, token) {
    var user = mongoose.model('User', userSchema);
    var currentTime = new Date();

    user.findById(userId)
        .exec()
        .then((user) => user.token === token && currentTime < user.tokenExpiration ? true : false)
        .catch((err) => {
            this.logger.debug('isUserTokenValid: error - ' + util.inspect(err));
            return false;
        });
};

UserService.prototype.generateToken = function (userName) {
    return User.findOneAndUpdate({
        name: userName
    }, {
        token: tokenGenerator(),
        tokenExpiration: moment(new Date()).add(15, 'm').toDate()
    }, {
        new: true
    }).exec();
};

module.exports = UserService;