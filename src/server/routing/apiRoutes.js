var express = require('express');
var router = express.Router();
var log4js = require('log4js');
var bodyParser = require('body-parser');
var UserController = require('../controllers/userController');
var jwtAuth = require('./middleware/auth');

var userController = new UserController();
var jsonParser = bodyParser.json();
var logger = log4js.getLogger('debugLog');

router.use(jwtAuth);

router.get('/user', function (req, res) {
	userController.getUser(req, res);
});

router.post('/user/category', jsonParser, function (req, res) {
	return userController.addCategory(req, res);
})

router.get('/token/validate', function (req, res) {
	if (req.user) {
		res.json({ isValid: true });
	} else {
		res.status(401).end();
	}
});

module.exports = router;