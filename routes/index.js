var express = require('express');
var router = express.Router();
const fs = require('fs');
var pem2jwk = require('pem-jwk').pem2jwk;

/* GET home page. */
router.get('/', function(req, res, next) {
  res.render('index', { title: 'Express' });
});

// well-known
router.get('/.well-known/openid-configuration', function(req, res, next) {
  var metadata = {
      issuer: 'https://' + req.headers.host,
      authorization_endpoint: 'https://' + req.headers.host + '/ida/authorize',
      token_endpoint: 'https://' + req.headers.host + '/ida/token',
      token_endpoint_auth_methods_supported: [
          'client_secret_post'
      ],
      jwks_uri: 'https://' + req.headers.host + '/jwks',
      userinfo_endpoint: 'https://' + req.headers.host + '/ida/userinfo',
      response_modes_supported: 'query',
      subject_types_supported: 'pairwise',
      id_token_signing_alg_values_supported: [
          'RS256'
      ],
      response_types_supported: [
          'code'
      ],
      scopes_supported: [
          'openid'
      ],
      claims_supported: [
          'sub',
          'given_name',
          'family_name',
          'email'
      ]
  }
  res.send(metadata);
});

// jwks
router.get('/jwks', function(req, res, next) {
  try{
      var str = fs.readFileSync('./private_key.pem', 'utf-8')
      var jwk = pem2jwk(str);
      res.send(jwk);
  }catch(e){
      res.send(e);
  }
});



module.exports = router;
