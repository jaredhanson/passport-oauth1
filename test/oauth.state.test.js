var OAuthStrategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai');


describe('OAuthStrategy', function() {
  
  describe('issuing authorization request with state store', function() {
    
    describe('that redirects to service provider without state', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        store: true
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
            req.session = {};
          })
          .authenticate();
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        expect(request.session['oauth']['state']).to.be.undefined;
      });
    }); // that redirects to service provider without state
    
    describe('that redirects to service provider with state', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        store: true
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
            req.session = {};
          })
          .authenticate({ state: { beep: 'boop' } });
      });
  
      it('should be redirected', function() {
        expect(url).to.equal('https://www.example.com/oauth/authorize?oauth_token=hh5s93j4hdidpola');
      });
    
      it('should store token and token secret in session', function() {
        expect(request.session['oauth']).to.not.be.undefined;
        expect(request.session['oauth']['oauth_token']).to.equal('hh5s93j4hdidpola');
        expect(request.session['oauth']['oauth_token_secret']).to.equal('hdhd0244k9j7ao03');
        expect(request.session['oauth']['state']).to.deep.equal({ beep: 'boop' });
      });
    }); // that redirects to service provider with state
    
    describe('that errors due to lack of session support in app', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        store: true
      }, function() {});
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        if (Object.keys(extraParams).length !== 1) { return callback(new Error('incorrect extraParams argument')); }
        if (extraParams.oauth_callback !== undefined) { return callback(new Error('incorrect oauth_callback argument')); }
    
        callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
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
        expect(err.message).to.equal('OAuth authentication requires session support. Did you forget to use express-session middleware?');
      });
    }); // that errors due to lack of session support in app
    
  });
  
  describe('processing response to authorization request with state store', function() {
    
    describe('that was approved without state', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        store: true
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
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
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
        expect(info.state).to.be.undefined;
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved without state
    
    describe('that was approved with state', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        store: true
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return callback(new Error('incorrect tokenSecret argument')); }
        if (typeof profile !== 'object') { return done(new Error('incorrect profile argument')); }
        if (Object.keys(profile).length !== 0) { return done(new Error('incorrect profile argument')); }
    
        return done(null, { id: '1234' }, { message: 'Hello' });
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
            req.session = {};
            req.session['oauth'] = {};
            req.session['oauth']['oauth_token'] = 'hh5s93j4hdidpola';
            req.session['oauth']['oauth_token_secret'] = 'hdhd0244k9j7ao03';
            req.session['oauth']['state'] = { beep: 'boop' };
          })
          .authenticate();
      });
  
      it('should supply user', function() {
        expect(user).to.be.an.object;
        expect(user.id).to.equal('1234');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
        expect(info.state).to.deep.equal({ beep: 'boop' });
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved with state
    
  });
  
});
