var OAuthStrategy = require('../lib/strategy')
  , chai = require('chai')
  , util = require('util');


describe('OAuthStrategy subclass', function() {
  
  describe('that overrides userProfile', function() {
    function FooOAuthStrategy(options, verify) {
      OAuthStrategy.call(this, options, verify);
    }
    util.inherits(FooOAuthStrategy, OAuthStrategy);

    FooOAuthStrategy.prototype.userProfile = function(token, tokenSecret, params, done) {
      if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
      if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
      
      return done(null, { username: 'jaredhanson', location: 'Oakland, CA' });
    };
    
    
    
    describe('fetching user profile', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile.username != 'jaredhanson') { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // fetching user profile
    
    describe('error fetching user profile', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('failed to load user profile'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
      var request
        , err

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
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

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error)
        expect(err.message).to.equal('failed to load user profile');
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // error fetching user profile
    
    describe('skipping user profile due to skipUserProfile option set to true', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: true
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // skipping user profile due to skipUserProfile option set to true
    
    describe('not skipping user profile due to skipUserProfile returning false', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function() {
          return false;
        }
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile.username != 'jaredhanson') { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // not skipping user profile due to skipUserProfile returning false
    
    describe('skipping user profile due to skipUserProfile returning true', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function() {
          return true;
        }
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // skipping user profile due to skipUserProfile returning true
    
    describe('not skipping user profile due to skipUserProfile asynchronously returning false', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function(token, tokenSecret, done) {
          if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
          if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
          
          return done(null, false);
        }
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile.username != 'jaredhanson') { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234', username: profile.username }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
        expect(user.username).to.equal('jaredhanson');
      });

      it('should supply info', function() {
        expect(info).to.be.an.object;
        expect(info.message).to.equal('Hello');
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // not skipping user profile due to skipUserProfile returning false
    
    describe('skipping user profile due to skipUserProfile returning true', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret',
        skipUserProfile: function(token, tokenSecret, done) {
          if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
          if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
          
          return done(null, true);
        }
      }, function(token, tokenSecret, profile, done) {
        if (token != 'nnch734d00sl2jdk') { return done(new Error('incorrect token argument')); }
        if (tokenSecret != 'pfkkdhi9sl3r4s00') { return done(new Error('incorrect tokenSecret argument')); }
        if (profile !== undefined) { return done(new Error('incorrect profile argument')); }
        
        return done(null, { id: '1234' }, { message: 'Hello' });
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        if (token != 'hh5s93j4hdidpola') { return callback(new Error('incorrect token argument')); }
        if (tokenSecret != 'hdhd0244k9j7ao03') { return callback(new Error('incorrect tokenSecret argument')); }
        if (verifier != 'hfdp7dh39dks9884') { return callback(new Error('incorrect verifier argument')); }
        
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
    
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
      });
  
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // skipping user profile due to skipUserProfile returning true
    
  }); // that overrides userProfile
  
});
