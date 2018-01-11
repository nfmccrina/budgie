var express = require('express');
var router = express.Router();
var log4js = require('log4js');
var bodyParser = require('body-parser');
var AccountController = require('../../controllers/accountController');

var accountController = new AccountController();
var jsonParser = bodyParser.json();
var logger = log4js.getLogger('debugLog');

router.post('/account/register', jsonParser, function (req, res) {
	logger.debug('received POST at /api/account/register');

	accountController.register(req, res);
});

router.post('/account/login', jsonParser, function (req, res) {
	logger.debug('received POST at /api/account/login');

	accountController.login(req, res);
});

module.exports = router;