/**
 * Dependencies
 */
var express = require('express');
var db = require('../db');
var dotenv = require('dotenv').config()
var http = require('./http');
var user = require('./user');
var admin = require('./admin');
var debug = require('debug')('iotgo');

/**
 * Connect to database first
 */
db.connect(process.env.DB_URL, {useNewUrlParser: process.env.DB_OPTIONS_USE_NEW_PARSER});
db.connection.on('error', function (err) {
  debug('Connect to DB failed!');
  debug(err);
  process.exit(1);
});
db.connection.on('open', function () {
  debug('Connect to DB successful!');
});

var router = express.Router();

router.route('/http').post(http).all(function (req, res) {
  res.send(405).end();
});

router.use('/user', user);
router.use('/admin', admin);

module.exports = router;