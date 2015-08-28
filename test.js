var paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should randomize', function() {
    paeonia.randomizeSync();
  });
});
