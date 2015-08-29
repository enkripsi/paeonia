#include <nan.h>
#include "rsa_pubkey.h"

void InitAll(v8::Local<v8::Object> exports) {
  paeonia::RSAPubKey::Init(exports);
}

NODE_MODULE(paeonia, InitAll)
