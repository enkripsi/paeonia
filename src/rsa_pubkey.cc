#include "rsa_pubkey.h"

#include <botan/block_cipher.h>
#include <botan/aes_ssse3.h>
#include <botan/aes_ni.h>
#include <botan/cpuid.h>
#include <botan/aes.h>

#include <iostream>

namespace paeonia {

class GenerateKeyPairWorker : public Nan::AsyncWorker {
  public:
    GenerateKeyPairWorker(
        Nan::Callback* callback,
        size_t keySize,
        RSAPubKey& pubKey
        )
      : Nan::AsyncWorker(callback), keySize(keySize), pubKey(pubKey)
    {}

    void Execute() {
      try {
        Botan::Block_Cipher_Fixed_Params<16, 16>* AES;
        if (Botan::CPUID::has_aes_ni()) {
          AES = new Botan::AES_128_NI();
        }
        else if (Botan::CPUID::has_ssse3()) {
          AES = new Botan::AES_128_SSSE3();
        }
        else { 
          AES = new Botan::AES_128();
        }
        pubKey.rng = new Botan::ANSI_X931_RNG(AES, Botan::RandomNumberGenerator::make_rng());
        pubKey.key = new Botan::RSA_PrivateKey(*pubKey.rng, keySize);
      } catch (std::exception& e) {
        SetErrorMessage(e.what());
      }
    }

    void HandleOKCallback() {
      v8::Local<v8::Value> argv[] = {
        Nan::Null()
      };
      callback->Call(1, argv);
    }
    
    ~GenerateKeyPairWorker() {}

  private:
    size_t keySize;
    RSAPubKey& pubKey;
};

Nan::Persistent<v8::Function> RSAPubKey::constructor;

RSAPubKey::RSAPubKey(size_t keySize) 
  : keySize(keySize) {}

RSAPubKey::~RSAPubKey() {
  if (key) {
    delete key;
  }
  if (rng) {
    delete rng;
  }
}

void RSAPubKey::Init(v8::Local<v8::Object> exports) {
  Nan::HandleScope scope;

  v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
  tpl->SetClassName(Nan::New("RSAPubKey").ToLocalChecked());
  tpl->InstanceTemplate()->SetInternalFieldCount(1);
  
  // prototypes here
  Nan::SetPrototypeMethod(tpl, "generateKeyPair", GenerateKeyPair);
  Nan::SetPrototypeMethod(tpl, "encode", Encode);

  constructor.Reset(tpl->GetFunction());
  exports->Set(Nan::New("RSAPubKey").ToLocalChecked(), tpl->GetFunction());
}

void RSAPubKey::New(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  if (info.IsConstructCall()) {
    size_t length = info[0]->IsUndefined() ? 4096 : info[0]->Uint32Value();
    RSAPubKey* obj = new RSAPubKey(length);
    obj->Wrap(info.This());
    info.GetReturnValue().Set(info.This());
  } else {
    const int argc = 1;
    v8::Local<v8::Value> argv[argc] = { info[0] };
    v8::Local<v8::Function> cons = Nan::New<v8::Function>(constructor);
    info.GetReturnValue().Set(cons->NewInstance(argc, argv));
  }
}

void RSAPubKey::GenerateKeyPair(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  RSAPubKey* obj = Nan::ObjectWrap::Unwrap<RSAPubKey>(info.Holder());
  Nan::Callback *callback = new Nan::Callback(info[0].As<v8::Function>());
  Nan::AsyncQueueWorker(new GenerateKeyPairWorker(callback, obj->keySize, *obj));
}

void RSAPubKey::Encode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  // should accept options object: { password: '', encode: 'BER' or 'DER'}, if password is provided, then it needs to serialize privateKey
  RSAPubKey* obj = Nan::ObjectWrap::Unwrap<RSAPubKey>(info.Holder());
  std::string publicKeyString = Botan::X509::PEM_encode(*obj->key);
  info.GetReturnValue().Set(Nan::New((char*) publicKeyString.c_str(), publicKeyString.size()).ToLocalChecked());
}

};

