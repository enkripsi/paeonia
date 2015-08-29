#include "rsa_pubkey.h"

#include <botan/block_cipher.h>
#include <botan/aes_ssse3.h>
#include <botan/aes_ni.h>
#include <botan/cpuid.h>
#include <botan/aes.h>

#include <iostream>

inline std::string to_upper(std::string str)
{
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);
    return str;
}

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

void RSAPubKey::GetEncodedPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info, const RSAPubKey* obj, const std::string& encoding) {
  std::string publicKeyString = Botan::X509::PEM_encode(*obj->key);
  info.GetReturnValue().Set(Nan::New((char*) publicKeyString.c_str(), publicKeyString.size()).ToLocalChecked());
}

void RSAPubKey::Encode(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  // should accept options object: { password: '', encoding: 'BER' or 'PEM'}, if password is provided, then it needs to serialize privateKey
  RSAPubKey* obj = Nan::ObjectWrap::Unwrap<RSAPubKey>(info.Holder());
  
  if (info.Length() > 0 && !info[0]->IsObject()) {
    Nan::ThrowTypeError("Option should be an object.");
    return;
  }
  
  if (!info.Length()) {
    GetEncodedPublicKey(info, obj);
    return;
  }

  v8::Local<v8::Object> option = info[0]->ToObject();
  v8::Local<v8::Value> password = Nan::Get(option, Nan::New("password").ToLocalChecked()).ToLocalChecked();
  v8::Local<v8::Value> encoding = Nan::Get(option, Nan::New("encoding").ToLocalChecked()).ToLocalChecked();
  
  std::string passwordString(*v8::String::Utf8Value(Nan::To<v8::String>(password).ToLocalChecked()));
  std::string encodingString(*v8::String::Utf8Value(Nan::To<v8::String>(encoding).ToLocalChecked()));
  encodingString = to_upper(encodingString);

  if (password->IsUndefined()) {
    GetEncodedPublicKey(info, obj, encodingString);
    return;
  }

  std::string keyString;
  keyString = passwordString != "" ? Botan::PKCS8::PEM_encode(*obj->key, *obj->rng, passwordString) : Botan::PKCS8::PEM_encode(*obj->key);
  keyString.append(Botan::X509::PEM_encode(*obj->key));
  info.GetReturnValue().Set(Nan::New((char*) keyString.c_str(), keyString.size()).ToLocalChecked()); 
}

};

