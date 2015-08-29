var Paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should generate RSA key pair', function(done) {
    var rsaPubKey = new Paeonia.RSAPubKey(4096);
    rsaPubKey.generateKeyPair(function(err) {
      var pub = rsaPubKey.encode({password: '', encoding: 'PEM'});
      pub.indexOf('PRIVATE').should.not.be.equal(-1);
      pub.indexOf('PUBLIC').should.not.be.equal(-1);
      done(err);     
    });
  });
});
