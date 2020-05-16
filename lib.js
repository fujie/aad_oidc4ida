var url = require('url');

module.exports.addQueryTo = (href, query) => {
  const urlObject = url.parse(href, true); // (1)

  urlObject.search = undefined; // (2)
  Object.assign(urlObject.query, query);

  return url.format(urlObject);
};

module.exports.redirect_uri = (req) => {
    if(req.headers.host == 'localhost:3000'){
        return req.protocol + '://' + req.headers.host + '/oauth/cb';
    }else{
        // for glitch(glitch returns http eventhough accessing with https scheme)
        return 'https://' + req.headers.host + '/oauth/cb';
    }        
}
