var OAuthStrategy = require('../lib/strategy')
  , InternalOAuthError = require('../lib/errors/internaloautherror')
  , chai = require('chai')
  , util = require('util');


describe('OAuthStrategy subclass', function() {
    
  describe('that overrides parseErrorResponse', function() {
    function FooOAuthStrategy(options, verify) {
      OAuthStrategy.call(this, options, verify);
    }
    util.inherits(FooOAuthStrategy, OAuthStrategy);

    FooOAuthStrategy.prototype.parseErrorResponse = function(body, status) {
      if (status === 666) { throw new Error('something went horribly wrong'); }
  
      var e = new Error('Custom OAuth error');
      e.body = body;
      e.status = status;
      return e;
    }
    
    
    describe('issuing authorization request that errors due to request token request error', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        return callback({ statusCode: 500, data: 'Invalid consumer key' });
      }
    
    
      var request, err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('Custom OAuth error');
        expect(err.body).to.equal('Invalid consumer key');
        expect(err.status).to.equal(500);
      });
    }); // issuing authorization request that errors due to request token request error
    
    describe('processing response to authorization request that errors due to access token request error', function() {
      var strategy = new FooOAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function(token, tokenSecret, profile, done) {
          return done(new Error('verify callback should not be called'));
        });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback({ statusCode: 500, data: 'Invalid request token' });
      }
    
    
      var request, err;

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
          .authenticate({ scope: 'foo' });
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('Custom OAuth error');
        expect(err.body).to.equal('Invalid request token');
        expect(err.status).to.equal(500);
      });
    }); // processing response to authorization request that errors due to access token request error
    
    describe('and throws from within implementation', function() {
      var strategy = new FooOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        return callback({ statusCode: 666 });
      }
    
    
      var request, err;

      before(function(done) {
        chai.passport.use(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate();
      });

      it('should error with generic error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain request token');
        expect(err.oauthError).to.not.be.undefined;
      });
    }); // and throws from within implementation
    
  }); // that overrides parseErrorResponse
  
});
