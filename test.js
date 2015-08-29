var paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should randomize', function(done) {
    paeonia.generateKeys(4096, function(err, keys) {
      if (err)
        return done(err);
      console.log(keys);
      done();
    });
  });
});
