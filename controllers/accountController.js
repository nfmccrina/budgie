var log4js = require('log4js');
var util = require('util');
var UserService = require('../services/userService');

const saltRounds = 10;

function AccountController () {
    this.logger = log4js.getLogger('debugLog');
    this.userService = new UserService();
}

AccountController.prototype.register = function (req, res) {
    this.logger.debug('AccountController.register invoked');

    if (!req.body || !req.body.name || !req.body.pwd) {
        this.logger.debug('invalid data: req.body = ' + util.inspect(req.body));
        res.status(400).send('Bad Request');
    }

    this.userService.addUser(req.body.name, req.body.pwd)
    	.then((user) => res.json(user))
        .catch((err) => {
            this.logger.debug('error: ' + util.inspect(err));
            res.status('500').send('Server Error');
        });
};

AccountController.prototype.login = function (req, res) {
	this.logger.debug('AccountController.login invoked');

	if (!req.body || !req.body.name || !req.body.pwd) {
		this.logger.debug('invalid data: req.body = ' + util.inspect(req.body));
        res.status(400).send('Bad Request');
	}

	this.userService.loginUser(req.body.name, req.body.pwd)
		.then((result) => res.json(result))
		.catch((err) => {
			this.logger.debug('error: ' + util.inspect(err));
            res.status('500').send('Server Error');
		});
}

module.exports = AccountController;