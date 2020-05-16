var express = require('express');
const request = require('request-promise');
const jwt = require('jsonwebtoken');
const fs = require('fs');
var router = express.Router();
var lib = require('../lib.js');
var conf = require('../config.js');

/* Authorization Endpoint */
router.get('/authorize', (req, res) => {
    // get claims from request
    var _claims = req.query.claims;
    // redirect to Azure AD
    var target = lib.addQueryTo(conf.AAD_AuthZ, {
            response_type: 'code',
            scope: 'openid User.Read',
            client_id: req.query.client_id,
            state: req.query.state,
            redirect_uri: req.query.redirect_uri });
    res.redirect(target);
});
  
/* Token Endpoint */
router.post('/token', async (req,res) => {
    try{
        let response_from_aad_token = await request({
            url: conf.AAD_Token,
            method: "POST",
            form: {
                grant_type: 'authorization_code',
                code: req.body.code,
                client_id: req.body.client_id,
                client_secret: req.body.client_secret,
                redirect_uri: req.body.redirect_uri
            },
            json: true
        })
        console.log(response_from_aad_token);
        // extract response and re-generate id_token with verified claims
        let decoded_jwt = jwt.decode(response_from_aad_token.id_token)

        // get additional claims using graph api
        let response_from_graph = await request({
            url: conf.AAD_Graph + "/v1.0/me?$select=id,userPrincipalName," + conf.AAD_ExtPrefix + "_verifiedClaims," + conf.AAD_ExtPrefix + "_verification",
            method: "GET",
            headers: {
                'Authorization': 'Bearer ' + response_from_aad_token.access_token,
                'Content-Type': 'application/json'
            }
        })
        console.log(response_from_graph);
        var user = JSON.parse(response_from_graph);
        // get properties from user object
        for (var prop in user){
            if(prop.includes('_verification')){
              var _verification = {
                trustframework: user[prop].trustframework,
                evidenceType: user[prop].evidenceType,
                evidenceMethod: user[prop].evidenceMethod,
                evidenceDocumentType: user[prop].evidenceDocumentType,
                evidenceDocumentIssuerName: user[prop].evidenceDocumentIssuerName,
                evidenceDocumentIssuerCountry: user[prop].evidenceDocumentIssuerCountry,
                evidenceDateOfIssurance: user[prop].evidenceDateOfIssurance,
                evidenceDateOfExpiry: user[prop].evidenceDateOfExpiry
              }
            } else if(prop.includes('_verifiedClaims')){
              var _verifiedClaims = {
                familyName: user[prop].familyName,
                givenName: user[prop].givenName
              }
            }
        }
        // create new jwt.
        var privateKey = fs.readFileSync('./private_key.pem', 'utf-8')
        var new_jwt = null;
        if (typeof _verification !== 'undefined') {
            new_jwt = jwt.sign({
                sub: decoded_jwt.sub,
                iss: 'https://' + req.headers.host,
                aud: decoded_jwt.aud,
                iat: decoded_jwt.iat,
                exp: decoded_jwt.exp,
                email: decoded_jwt.email,
                verified_claims: {
                    verification: {
                        trust_framework: _verification.trustframework,
                        evidence: [
                            {
                                type: _verification.evidenceType,
                                method: _verification.evidenceMethod,
                                document: {
                                    type: _verification.evidenceDocumentType,
                                    issuer: {
                                        name: _verification.evidenceDocumentIssuerName,
                                        country: _verification.evidenceDocumentIssuerCountry
                                    },
                                    number: _verification.evidenceNumber,
                                    date_of_issuance: _verification.evidenceDateOfIssurance,
                                    date_of_expiry: _verification.evidenceDateOfExpiry
                                }
                            }
                        ]
                    },
                    claims: {
                        given_name: _verifiedClaims.givenName,
                        first_name: _verifiedClaims.familyName
                    }
                }
            }, privateKey, { algorithm: 'RS256' });    
        } else {
            new_jwt = jwt.sign({
                sub: decoded_jwt.sub,
                iss: 'https://' + req.headers.host,
                aud: decoded_jwt.aud,
                iat: decoded_jwt.iat,
                exp: decoded_jwt.exp,
                email: decoded_jwt.email,
            }, privateKey, { algorithm: 'RS256' });    
        }
        
        res.send({
            token_type: "bearer",
            scope: "openid",
            expires_in: response_from_aad_token.expires_in,
            access_token: response_from_aad_token.access_token,
            id_token: new_jwt
        });
    } catch(e){
        console.log(e);
    }
});
  
/* userInfo Endopoint */
router.get('/userinfo', (req, res) => {
    // require authorization
});

module.exports = router;
