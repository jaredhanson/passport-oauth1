var OAuthStrategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');
  
  
describe('OAuthStrategy', function() {
  
  describe('with custom request token store that accepts meta argument', function() {
    function CustomStore() {
    }

    CustomStore.prototype.get = function(req, token, meta, cb) {
      //return cb(null, info.tokenSecret, state);
    };

    CustomStore.prototype.set = function(req, token, tokenSecret, meta, cb) {
      console.log('CustomStore#set');
      console.log(token);
      console.log(tokenSecret)
      console.log(meta)
      
      if (token === '666') { return cb(new Error('something went wrong storing request token')); }
      if (token === '6666') { throw new Error('something went horribly wrong storing request token'); }
      
      if (token !== 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
      if (tokenSecret !== 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
      if (meta.requestTokenURL !== 'https://www.example.com/oauth/request_token') { return callback(new Error('incorrect meta.requestTokenURL argument')); }
      if (meta.accessTokenURL !== 'https://www.example.com/oauth/access_token') { return callback(new Error('incorrect meta.accessTokenURL argument')); }
      if (meta.userAuthorizationURL !== 'https://www.example.com/oauth/authorize') { return callback(new Error('incorrect meta.userAuthorizationURL argument')); }
      if (meta.consumerKey !== 'ABC123') { return callback(new Error('incorrect meta.consumerKey argument')); }
      
      req.customStoreSetCalled = req.customStoreSetCalled ? req.customStoreSetCalled++ : 1;
      
      cb(null);
    };

    CustomStore.prototype.destroy = function(req, token, meta, cb) {
      //cb();
    };
    
    
    describe('issuing authorization request', function() {
       
      describe('that redirects to service provider', function() {
       var strategy = new OAuthStrategy({
         requestTokenURL: 'https://www.example.com/oauth/request_token',
         accessTokenURL: 'https://www.example.com/oauth/access_token',
         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
         consumerKey: 'ABC123',
         consumerSecret: 'secret',
         requestTokenStore: new CustomStore()
       }, function() {});

       strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
         if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
         if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }

         callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
       }


       var request
         , url;

       before(function(done) {
         chai.passport.use(strategy)
           .redirect(function(u) {
             url = u;
             done();
           })
           .req(function(req) {
             request = req;
           })
           .authenticate();
       });

       it('should be redirected', function() {
         expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
       });

       it('should store request token in custom store', function() {
         expect(request.customStoreSetCalled).to.equal(1);
       });
      }); // that redirects to service provider
      
      describe('that errors due to custom store supplying error', function() {
       var strategy = new OAuthStrategy({
         requestTokenURL: 'https://www.example.com/oauth/request_token',
         accessTokenURL: 'https://www.example.com/oauth/access_token',
         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
         consumerKey: 'ABC123',
         consumerSecret: 'secret',
         requestTokenStore: new CustomStore()
       }, function() {});

       strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
         if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
         if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }

         callback(null, '666', 'hdhd0244k9j7ao03', {});
       }


       var request
         , err;

       before(function(done) {
         chai.passport.use(strategy)
           .error(function(e) {
             err = e;
             done();
           })
           .req(function(req) {
             request = req;
           })
           .authenticate();
       });

       it('should error', function() {
         expect(err).to.be.an.instanceof(Error);
         expect(err.message).to.equal('something went wrong storing request token');
       });
      }); // that errors due to custom store supplying error
      
      describe('that errors due to custom store throwing error', function() {
       var strategy = new OAuthStrategy({
         requestTokenURL: 'https://www.example.com/oauth/request_token',
         accessTokenURL: 'https://www.example.com/oauth/access_token',
         userAuthorizationURL: 'https://www.example.com/oauth/authorize',
         consumerKey: 'ABC123',
         consumerSecret: 'secret',
         requestTokenStore: new CustomStore()
       }, function() {});

       strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
         if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
         if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }

         callback(null, '6666', 'hdhd0244k9j7ao03', {});
       }


       var request
         , err;

       before(function(done) {
         chai.passport.use(strategy)
           .error(function(e) {
             err = e;
             done();
           })
           .req(function(req) {
             request = req;
           })
           .authenticate();
       });

       it('should error', function() {
         expect(err).to.be.an.instanceof(Error);
         expect(err.message).to.equal('something went horribly wrong storing request token');
       });
      }); // that errors due to custom store throwing error
 
    }); // issuing authorization request
    
  }); // with custom request token store that accepts meta argument
  
});
