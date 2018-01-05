var MongoClient = require('mongodb').MongoClient;

function buildMongoURL () {
    return 'mongodb://' + process.env.MONGODB_USERNAME + ':' + process.env.MONGODB_PASSWORD + '@' + process.env.MONGODB_HOST + ':' + process.env.MONGODB_PORT + '/' + process.env.MONGODB_DATABASE;
}
var client = new MongoClient(buildMongoURL(), 