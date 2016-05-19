var express  = require('express');
var bodyParser = require('body-parser');
var app      = express();
var template = require('./views/index.jade');
var jwt = require('jsonwebtoken');

require('dotenv').config();
app.use(function(req, res, next) {
 if (req.webtaskContext) return next();
 
 req.webtaskContext = {};
 req.webtaskContext.secrets = {};
 Object.keys(process.env).forEach(function(k) { req.webtaskContext.secrets[k] = process.env[k]; })
 next();
});

app.use(bodyParser.json());

app.get('/', function (req, res) {
  res.header("Content-Type", 'text/html');
  res.status(200).send(template());
});

app.post('/exchange', function(req, res) {
  var id_token = req.body.id_token;
  var privateKey = req.webtaskContext.secrets.FIREBASE_SERVICE_PRIVATE_KEY;
  console.log(privateKey);
  var clientSecret = req.webtaskContext.secrets.AUTH0_CLIENT_SECRET;
  jwt.verify(id_token, new Buffer(clientSecret, 'base64'), function(err, decoded) {
    if (err) return res.json({ error: 'access_denied', error_description: err.toString() }, 401);
    jwt.sign({
        uid: decoded.sub || decoded.user_id, 
        sub: req.webtaskContext.secrets.FIREBASE_SERVICE_ACCOUNT_ID
        // add more properties if needed
      }, 
      privateKey.replace(/\\[n]/g, '\n'), 
      {
        audience: 'https://identitytoolkit.googleapis.com/google.identity.identitytoolkit.v1.IdentityToolkit', 
        expiresIn: 3000, 
        issuer: req.webtaskContext.secrets.FIREBASE_SERVICE_ACCOUNT_ID,
        algorithm: 'RS256' 
      }, function(firebase_token) { 
          res.json({firebase_token: firebase_token});
      });
  });
})

module.exports = app;
