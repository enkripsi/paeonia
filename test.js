var Paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should generate RSA key pair', function(done) {
    var rsaPubKey = new Paeonia.RSAPubKey(4096);
    rsaPubKey.generateKeyPair(function(err) {
      var pub = rsaPubKey.encode({encoding: 'PEM'});
      pub.indexOf('PUBLIC').should.not.be.equal(-1);
      done(err);     
    });
  });
  it('should load an RSA public key', function(done) {
    var rsaPubKey = new Paeonia.RSAPubKey(4096);
    rsaPubKey.loadPublicKey(__dirname + '/data/pub.txt', done);
  });
});
