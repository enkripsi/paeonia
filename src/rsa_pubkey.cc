#include "rsa_pubkey.h"

#include <iostream>

namespace paeonia {

inline std::string to_upper(std::string str)
{
  std::transform(str.begin(), str.end(), str.begin(), ::toupper);
  return str;
}

class LoadKeyWorker : public Nan::AsyncWorker {
  public:
    LoadKeyWorker(
        Nan::Callback* callback,
        RSAPubKey& pubKey,
        const std::string& publicKeyPath,
        const std::string& privateKeyPath = "",
        const std::string& password = ""
        )
      : Nan::AsyncWorker(callback), publicKeyPath(publicKeyPath), privateKeyPath(privateKeyPath), pubKey(pubKey)
    {}
  
  void Execute() {
    try {
      if (publicKeyPath.size() > 0) {
        auto publicKey = Botan::X509::load_key(publicKeyPath);
        if (!publicKey) {
          SetErrorMessage("Cannot load public key.");
          return;
        }
        pubKey.publicKey = dynamic_cast<Botan::RSA_PublicKey*>(publicKey);
        pubKey.keySize = publicKey->max_input_bits() + 1;
      }

      if (privateKeyPath.size() > 0) {
        if (!pubKey.rng) {
          pubKey.rng = Botan::AutoSeeded_RNG::make_rng();
        }
        auto privateKey = Botan::PKCS8::load_key(privateKeyPath, *pubKey.rng, password);
        if (!privateKey) {
          SetErrorMessage("Cannot load private key.");
          return;
        }
        pubKey.privateKey = dynamic_cast<Botan::RSA_PrivateKey*>(privateKey);
        if (!pubKey.publicKey && publicKeyPath.size() == 0) {
          pubKey.keySize = privateKey->max_input_bits() + 1;
        }
      }
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

  private:
    std::string publicKeyPath;
    std::string privateKeyPath;
    std::string password;
    RSAPubKey& pubKey;
};

class GenerateKeyPairWorker : public Nan::AsyncWorker {
  public:
    GenerateKeyPairWorker(
        Nan::Callback* callback,
        RSAPubKey& pubKey,
        size_t keySize = 4096
        )
      : Nan::AsyncWorker(callback), keySize(keySize), pubKey(pubKey)
    {}

    void Execute() {
      try {
        if (!pubKey.rng) {
          pubKey.rng = Botan::AutoSeeded_RNG::make_rng();
        }
        if (pubKey.privateKey) {
          delete pubKey.privateKey;
        }
        pubKey.privateKey = new Botan::RSA_PrivateKey(*pubKey.rng, keySize);
        pubKey.publicKey = dynamic_cast<Botan::RSA_PublicKey*>(pubKey.privateKey);
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
  : keySize(keySize), publicKey(NULL), privateKey(NULL), rng(NULL) {}

RSAPubKey::~RSAPubKey() {
  if (publicKey) {
    delete publicKey;
  }
  if (privateKey) {
    delete privateKey;
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
  Nan::SetPrototypeMethod(tpl, "loadPublicKey", LoadPublicKey);

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
  Nan::AsyncQueueWorker(new GenerateKeyPairWorker(callback, *obj, obj->keySize));
}

void RSAPubKey::GetEncodedPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info, const RSAPubKey* obj, const std::string& encoding) {
  if (!obj->publicKey) {
    info.GetReturnValue().SetUndefined();
    return;
  }
  std::string publicKeyString = Botan::X509::PEM_encode(*obj->publicKey);
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
  if (!obj->privateKey) {
    info.GetReturnValue().SetUndefined();
    return;
  }

  keyString = passwordString != "" ? Botan::PKCS8::PEM_encode(*obj->privateKey, *obj->rng, passwordString) : Botan::PKCS8::PEM_encode(*obj->privateKey);
  keyString.append(Botan::X509::PEM_encode(*obj->privateKey));
  info.GetReturnValue().Set(Nan::New((char*) keyString.c_str(), keyString.size()).ToLocalChecked()); 
}

void RSAPubKey::LoadPublicKey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  // from buffer or from path using the load_key
  RSAPubKey* obj = Nan::ObjectWrap::Unwrap<RSAPubKey>(info.Holder());
  std::string path(*v8::String::Utf8Value(info[0]->ToString()));
  Nan::Callback *callback = new Nan::Callback(info[1].As<v8::Function>());
  Nan::AsyncQueueWorker(new LoadKeyWorker(callback, *obj, path));
}

void RSAPubKey::LoadPrivateKey(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  // from buffer or from path
}

void RSAPubKey::Encrypt(const Nan::FunctionCallbackInfo<v8::Value>& info) {
  // from buffer or from path
  // load public key or generate key pair
  // do encrypt buffer or string
}

};

