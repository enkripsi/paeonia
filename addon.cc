#include <nan.h>
#include "pk.h"

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New<v8::String>("generateKeys").ToLocalChecked(),
      Nan::GetFunction(Nan::New<v8::FunctionTemplate>(GenerateKeys)).ToLocalChecked()
      );
}

NODE_MODULE(paeonia, InitAll)
