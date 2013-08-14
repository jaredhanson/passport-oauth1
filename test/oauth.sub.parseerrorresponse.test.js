var chai = require('chai')
  , OAuthStrategy = require('../lib/strategy')
  , util = require('util')
  , InternalOAuthError = require('../lib/errors/internaloautherror');


function MockOAuthStrategy(options, verify) {
  OAuthStrategy.call(this, options, verify);
}
util.inherits(MockOAuthStrategy, OAuthStrategy);

MockOAuthStrategy.prototype.parseErrorResponse = function(body, status) {
  if (status !== 500) { throw new Error('Whoops'); }
  
  var e = new Error('Custom OAuth error');
  e.body = body;
  e.status = status;
  return e;
}


describe('OAuthStrategy', function() {
    
  describe('subclass that overrides parseErrorResponse function', function() {
    
    describe('parsing an error from request token endpoint', function() {
      var strategy = new MockOAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function(token, tokenSecret, profile, done) {
          if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
    
      // inject a "mock" oauth instance
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      }
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        return callback({ statusCode: 500, data: 'Invalid client key' });
      }
    
      describe('handling a request to be redirected with params', function() {
        var request, err;

        before(function(done) {
          chai.passport(strategy)
            .error(function(e) {
              err = e;
              done();
            })
            .req(function(req) {
              request = req;
              req.session = {};
            })
            .authenticate({ scope: 'foo' });
        });

        it('should error', function() {
          expect(err).to.be.an.instanceof(Error);
          expect(err.message).to.equal('Custom OAuth error');
          expect(err.body).to.equal('Invalid client key');
          expect(err.status).to.equal(500);
        });
      });
    });
    
    describe('parsing an error from access token endpoint', function() {
      var strategy = new MockOAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function(token, tokenSecret, profile, done) {
          if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
            return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
          }
          return done(null, false);
        });
    
      // inject a "mock" oauth instance
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback({ statusCode: 500, data: 'Invalid request token' });
      }
    
      strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
        return callback(null, 'hh5s93j4hdidpola', 'hdhd0244k9j7ao03', {});
      }
    
      describe('handling a request to be redirected with params', function() {
        var request, err;

        before(function(done) {
          chai.passport(strategy)
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
      });
    });
  });
  
  describe('handling an exception thrown while parsing error response', function() {
    var strategy = new MockOAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        if (token == 'nnch734d00sl2jdk' && tokenSecret == 'pfkkdhi9sl3r4s00') {
          return done(null, { id: '1234', profile: profile }, { message: 'Hello' });
        }
        return done(null, false);
      });
  
    // inject a "mock" oauth instance
    strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
      return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
    }
  
    strategy._oauth.getOAuthRequestToken = function(extraParams, callback) {
      return callback({ statusCode: 501, data: 'Invalid client key' });
    }
  
    describe('handling a request to be redirected with params', function() {
      var request, err;

      before(function(done) {
        chai.passport(strategy)
          .error(function(e) {
            err = e;
            done();
          })
          .req(function(req) {
            request = req;
            req.session = {};
          })
          .authenticate({ scope: 'foo' });
      });

      it('should error with generic error', function() {
        expect(err).to.be.an.instanceof(InternalOAuthError);
        expect(err.message).to.equal('Failed to obtain request token');
        expect(err.oauthError).to.not.be.undefined;
      });
    });
  });
  
});
