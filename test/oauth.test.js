var OAuthStrategy = require('../lib/strategy');


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
  
});
