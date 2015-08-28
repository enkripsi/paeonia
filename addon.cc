#include <nan.h>
#include "sync.h"

NAN_MODULE_INIT(InitAll) {
  Nan::Set(target, Nan::New<v8::String>("randomizeSync").ToLocalChecked(),
      Nan::GetFunction(Nan::New<v8::FunctionTemplate>(RandomizeSync)).ToLocalChecked()
      );
}

NODE_MODULE(paeonia, InitAll)
