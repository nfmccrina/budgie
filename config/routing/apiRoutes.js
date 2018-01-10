var express = require('express');
var router = express.Router();
var bodyParser = require('body-parser');
var UserController = require('../../controllers/userController');

var userController = new UserController();
var jsonParser = bodyParser.json();

router.post('/Users', jsonParser, (req, res) => userController.addUser(req, res));

module.exports = router;