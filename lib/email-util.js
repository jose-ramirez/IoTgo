var mixin = require('utils-merge');
var dotenv = require('dotenv').config()
var mailgun = require('mailgun-js')({
  apiKey: process.env.MAILGUN_API_KEY,
  domain: process.env.MAILGUN_DOMAIN
});
var debug = require('debug')('email-util');

exports.sendMail = function (mailOptions, callback) {
  mixin(mailOptions, {
    from: process.env.MAILGUN_FROM
  });
  debug('mailOptions:', mailOptions);
  mailgun.messages().send(mailOptions, function (error, body) {
    if (error) {
      debug('err:', error);
      callback(error);
      return;
    }
    debug('Email Send success!');
    callback(null, body);
  });
};