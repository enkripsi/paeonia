var paeonia = require('bindings')('paeonia.node')

describe('Paeonia', function() {
  it('should randomize', function() {
    console.log(paeonia.generateKeysSync(4096));
  });
});
