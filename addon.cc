#include <nan.h>
#include "sync.h"

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New<v8::String>("generateKeysSync").ToLocalChecked(),
      Nan::GetFunction(Nan::New<v8::FunctionTemplate>(GenerateKeysSync)).ToLocalChecked()
      );
}

NODE_MODULE(paeonia, InitAll)
