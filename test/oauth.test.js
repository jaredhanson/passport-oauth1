var OAuthStrategy = require('../lib/strategy')
  , chai = require('chai');


describe('OAuthStrategy', function() {
    
  describe('constructed', function() {
    var strategy = new OAuthStrategy({
      requestTokenURL: 'https://www.example.com/oauth/request_token',
      accessTokenURL: 'https://www.example.com/oauth/access_token',
      userAuthorizationURL: 'https://www.example.com/oauth/authorize',
      consumerKey: 'ABC123',
      consumerSecret: 'secret'
    }, function() {});
    
    it('should be named oauth', function() {
      expect(strategy.name).to.equal('oauth');
    });
  
    it('should have user agent header set by underlying oauth module', function() {
      expect(Object.keys(strategy._oauth._headers)).to.have.length(3);
      expect(strategy._oauth._headers['User-Agent']).to.equal('Node authentication');
    });
  }); // constructed
  
  describe('constructed without a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        });
      }).to.throw(TypeError, 'OAuthStrategy requires a verify callback');
    });
  }); // constructed without a verify callback
  
  describe('constructed without a requestTokenURL option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a requestTokenURL option');
    });
  }); // constructed without a requestTokenURL option
  
  describe('constructed without an accessTokenURL option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a accessTokenURL option');
    });
  }); // constructed without an accessTokenURL option
  
  describe('constructed without a userAuthorizationURL option', function() {
    it('should throw if constructed without a userAuthorizationURL option', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          consumerKey: 'ABC123',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a userAuthorizationURL option');
    });
  }); // constructed without a userAuthorizationURL option
  
  describe('constructed without a consumerKey option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerSecret: 'secret'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a consumerKey option');
    });
  }); // constructed without a consumerKey option
  
  describe('constructed without a consumerSecret option', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123'
        }, function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a consumerSecret option');
    });
  }); // constructed without a consumerSecret option
  
  describe('constructed with an empty string as consumerSecret option', function() {
    it('should not throw', function() {
      expect(function() {
        new OAuthStrategy({
          requestTokenURL: 'https://www.example.com/oauth/request_token',
          accessTokenURL: 'https://www.example.com/oauth/access_token',
          userAuthorizationURL: 'https://www.example.com/oauth/authorize',
          consumerKey: 'ABC123',
          consumerSecret: ''
        }, function() {});
      }).to.not.throw();
    });
  }); // constructed with an empty string as consumerSecret option'
  
  describe('constructed with only a verify callback', function() {
    it('should throw', function() {
      expect(function() {
        new OAuthStrategy(function() {});
      }).to.throw(TypeError, 'OAuthStrategy requires a requestTokenURL option');
    });
  }); // constructed with only a verify callback
  
  
  
  describe('issuing authorization request', function() {
    
    describe('that redirects to service provider', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
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
      });
    }); // that redirects to service provider
    
  });
  
  describe('processing response to authorization request', function() {
    
    describe('that was approved', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
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
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that was approved
    
    describe('that fails due to verify callback supplying false', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(null, false);
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(null, 'nnch734d00sl2jdk', 'pfkkdhi9sl3r4s00', {});
      };
    
    
      var request
        , info;
  
      before(function(done) {
        chai.passport.use(strategy)
          .fail(function(i) {
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
  
      it('should not supply info', function() {
        expect(info).to.be.undefined;
      });
    
      it('should remove token and token secret from session', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that fails due to verify callback supplying false
    
    describe('that errors due to request token not being found in session', function() {
      var strategy = new OAuthStrategy({
        requestTokenURL: 'https://www.example.com/oauth/request_token',
        accessTokenURL: 'https://www.example.com/oauth/access_token',
        userAuthorizationURL: 'https://www.example.com/oauth/authorize',
        consumerKey: 'ABC123',
        consumerSecret: 'secret'
      }, function(token, tokenSecret, profile, done) {
        return done(new Error('verify callback should not be called'));
      });
    
      strategy._oauth.getOAuthAccessToken = function(token, tokenSecret, verifier, callback) {
        return callback(new Error('OAuth#getOAuthAccessToken should not be called'));
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
            req.query['oauth_token'] = 'hh5s93j4hdidpola';
            req.query['oauth_verifier'] = 'hfdp7dh39dks9884';
            req.session = {};
          })
          .authenticate();
      });

      it('should error', function() {
        expect(err).to.be.an.instanceof(Error);
        expect(err.message).to.equal('Failed to find request token in session');
      });
    
      it('should leave session unmodified', function() {
        expect(request.session['oauth']).to.be.undefined;
      });
    }); // that errors due to request token not being found in session
    
  }); // processing response to authorization request
  
});
