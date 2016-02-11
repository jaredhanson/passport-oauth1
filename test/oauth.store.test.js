var OAuthStrategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');
  
  
describe('OAuthStrategy', function() {
  
  describe('with custom request token store that accepts meta argument', function() {
    function CustomStore() {
    }

    CustomStore.prototype.get = function(req, token, meta, cb) {
      if (token === '666') { return cb(new Error('something went wrong loading request token')); }
      if (token === '6666') { throw new Error('something went horribly wrong loading request token'); }
      
      if (token !== 'hh5s93j4hdidpola') { return cb(new Error('incorrect token argument')); }
      if (meta.requestTokenURL !== 'https://www.example.com/oauth/request_token') { return cb(new Error('incorrect meta.requestTokenURL argument')); }
      if (meta.accessTokenURL !== 'https://www.example.com/oauth/access_token') { return cb(new Error('incorrect meta.accessTokenURL argument')); }
      if (meta.userAuthorizationURL !== 'https://www.example.com/oauth/authorize') { return cb(new Error('incorrect meta.userAuthorizationURL argument')); }
      if (meta.consumerKey !== 'ABC123') { return callback(new Error('incorrect meta.consumerKey argument')); }
      
      req.customStoreGetCalled = req.customStoreGetCalled ? req.customStoreGetCalled++ : 1;
      return cb(null, 'hdhd0244k9j7ao03');
    };

    CustomStore.prototype.set = function(req, token, tokenSecret, meta, cb) {
      if (token === '666') { return cb(new Error('something went wrong storing request token')); }
      if (token === '6666') { throw new Error('something went horribly wrong storing request token'); }
      
      if (token !== 'hh5s93j4hdidpola') { return cb(new Error('incorrect token argument')); }
      if (tokenSecret !== 'hdhd0244k9j7ao03') { return cb(new Error('incorrect tokenSecret argument')); }
      if (meta.requestTokenURL !== 'https://www.example.com/oauth/request_token') { return cb(new Error('incorrect meta.requestTokenURL argument')); }
      if (meta.accessTokenURL !== 'https://www.example.com/oauth/access_token') { return cb(new Error('incorrect meta.accessTokenURL argument')); }
      if (meta.userAuthorizationURL !== 'https://www.example.com/oauth/authorize') { return cb(new Error('incorrect meta.userAuthorizationURL argument')); }
      if (meta.consumerKey !== 'ABC123') { return cb(new Error('incorrect meta.consumerKey argument')); }
      
      req.customStoreSetCalled = req.customStoreSetCalled ? req.customStoreSetCalled++ : 1;
      return cb(null);
    };

    CustomStore.prototype.destroy = function(req, token, meta, cb) {
      if (token !== 'hh5s93j4hdidpola') { return cb(new Error('incorrect token argument')); }
      if (meta.requestTokenURL !== 'https://www.example.com/oauth/request_token') { return cb(new Error('incorrect meta.requestTokenURL argument')); }
      if (meta.accessTokenURL !== 'https://www.example.com/oauth/access_token') { return cb(new Error('incorrect meta.accessTokenURL argument')); }
      if (meta.userAuthorizationURL !== 'https://www.example.com/oauth/authorize') { return cb(new Error('incorrect meta.userAuthorizationURL argument')); }
      if (meta.consumerKey !== 'ABC123') { return cb(new Error('incorrect meta.consumerKey argument')); }
      
      req.customStoreDestroyCalled = req.customStoreDestroyCalled ? req.customStoreDestroyCalled++ : 1;
      return cb();
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
    
    
    describe('processing response to authorization request', function() {
      
      describe('that was approved', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          requestTokenStore: new CustomStore()
        }, function(token, tokenSecret, profile, done) {
          if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
          if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
          if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
          if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
          return done(null, { id: '1234' });
        });
    
        strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
          if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
          if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
          if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
          return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
        };
    
    
        var request
          , user
          , info;
  
        before(function(done) {
          chai.passport.use(strategy)
            .success(function(u, i) {
              user = u;
              info = i;
              done();
            })
            .req(function(req) {
              request = req;
              req.query = {};
              req.query['oauth_token'] = 'hh5s93j4hdidpola';
              req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            })
            .authenticate();
        });
  
        it('should supply user', function() {
          expect(user).to.be.an.object;
          expect(user.id).to.equal('1234');
        });

        it('should supply info with no attributes', function() {
          expect(info).to.be.an.object;
          expect(Object.keys(info)).to.have.length(0);
        });
    
        it('should load request token from custom store', function() {
          expect(request.customStoreGetCalled).to.equal(1);
        });
        
        it('should remove request token from custom store', function() {
          expect(request.customStoreDestroyCalled).to.equal(1);
        });
      }); // that was approved
      
      describe('that errors due to custom store supplying error on get', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          requestTokenStore: new CustomStore()
        }, function(token, tokenSecret, profile, done) {
          if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
          if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
          if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
          if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
          return done(null, { id: '1234' });
        });
    
        strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
          if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
          if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
          if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
          return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
        };
    
    
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
              req.query = {};
              req.query['oauth_token'] = '666';
              req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went wrong loading request token');
        });
      }); // that errors due to custom store supplying error on get
      
      describe('that errors due to custom store throwing error on get', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          requestTokenStore: new CustomStore()
        }, function(token, tokenSecret, profile, done) {
          if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
          if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
          if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
          if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
          return done(null, { id: '1234' });
        });
    
        strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
          if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
          if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
          if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
          return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
        };
    
    
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
              req.query = {};
              req.query['oauth_token'] = '6666';
              req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went horribly wrong loading request token');
        });
      }); // that errors due to custom store throwing error on get
      
    });
    
  }); // with custom request token store that accepts meta argument
  
  
  describe('with custom request token store that accepts meta argument and errors on destroy', function() {
    function CustomStore() {
    }

    CustomStore.prototype.get = function(req, token, meta, cb) {
      req.customStoreGetCalled = req.customStoreGetCalled ? req.customStoreGetCalled++ : 1;
      return cb(null, 'hdhd0244k9j7ao03');
    };

    CustomStore.prototype.set = function(req, token, tokenSecret, meta, cb) {
      req.customStoreSetCalled = req.customStoreSetCalled ? req.customStoreSetCalled++ : 1;
      return cb(null);
    };

    CustomStore.prototype.destroy = function(req, token, meta, cb) {
      if (token === '666') { return cb(new Error('something went wrong removing request token')); }
      if (token === '6666') { throw new Error('something went horribly wrong removing request token'); }
      
      req.customStoreDestroyCalled = req.customStoreDestroyCalled ? req.customStoreDestroyCalled++ : 1;
      return cb();
    };
    
    
    describe('processing response to authorization request', function() {
      
      describe('that errors due to custom store supplying error on destroy', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          requestTokenStore: new CustomStore()
        }, function(token, tokenSecret, profile, done) {
          return done(null, { id: '1234' });
        });
    
        strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
          return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
        };
    
    
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
              req.query = {};
              req.query['oauth_token'] = '666';
              req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went wrong removing request token');
        });
      }); // that errors due to custom store supplying error on destroy
      
      describe('that errors due to custom store throwing error on destroy', function() {
        var strategy = new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret',
          requestTokenStore: new CustomStore()
        }, function(token, tokenSecret, profile, done) {
          return done(null, { id: '1234' });
        });
    
        strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
          return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
        };
    
    
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
              req.query = {};
              req.query['oauth_token'] = '6666';
              req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            })
            .authenticate();
        });
  
        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('something went horribly wrong removing request token');
        });
      }); // that errors due to custom store throwing error on destroy
      
    });
    
  }); // with custom request token store that accepts meta argument and errors on destroy
  
});
