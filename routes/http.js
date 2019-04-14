/**
 * Dependencies
 */
var protocol = require('../protocol');
var dotenv = require('dotenv').config()

module.exports = function (req, res) {
  if (req.header('Host') !== process.env.HOST ||
      req.header('Content-Type') !== 'application/json') {
    res.status(400).end();
    return;
  }

  protocol.postRequest(req.body, function (resBody) {
    res.send(resBody);
  });
};