var Paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should generate RSA key pair', function(done) {
    var rsaPubKey = new Paeonia.RSAPubKey(4096);
    rsaPubKey.generateKeyPair(function(err) {
      rsaPubKey.encode().length.should.above(0);
      done(err);     
    });
  });
});
