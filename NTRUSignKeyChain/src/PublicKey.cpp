//
// Created by sunny on 2020/9/16.
//

#include "PublicKey.h"

#ifdef __cplusplus
extern "C" {
#endif
#include <ntrusign/bsparseconv.h>
#include <ntrusign/crypto_stream_salsa20.h>
#include <ntrusign/fastrandombytes.h>
#include <ntrusign/formatc.h>
#include <ntrusign/poly.h>
#include <ntrusign/randombytes.h>
#ifdef __cplusplus
}
#endif


namespace ndn {
  namespace security {
    namespace ntru {
      inline int doVerify(const unsigned char *h, const int64 *z, const int64 *pubkey,
                          const unsigned char *message, const int msglen) {
        return verify(h, z, pubkey, message, msglen);
      }

      /////////////////////////////////////////////////////////////////////////////////////////
      //// Public Key
      /////////////////////////////////////////////////////////////////////////////////////////
      class PublicKey::Impl {
      public:
        Impl() noexcept = default;

        ~Impl() = default;

      public:
        int64 pubKey[PASS_N] = {0};
      };

      PublicKey::PublicKey() : mImpl(std::make_unique<Impl>()) {

      }

      PublicKey::~PublicKey() {

      }

      std::unique_ptr<PublicKey> PublicKey::derivePublicKey(const PrivateKey &privateKey) {
        auto buffer = privateKey.derivePublicKey();
        auto publicKey = std::make_unique<PublicKey>();
        std::move(buffer->begin(), buffer->end(), std::begin(publicKey->mImpl->pubKey));
        return publicKey;
      }

      bool PublicKey::verify(const unsigned char *message, int messageLen, const Signature &signature) {
        auto result = doVerify(signature.h, signature.data, this->mImpl->pubKey, message, messageLen);
        return result == VALID;
      }

      bool PublicKey::verify(const char *message, int messageLen, const Signature &signature) {
        return verify(reinterpret_cast<const unsigned char *>(message), messageLen, signature);
      }

      bool PublicKey::verify(const std::string &msg, const Signature &signature) {
        return verify(msg.c_str(), msg.size(), signature);
      }

      ConstBufferPtr PublicKey::exportPrivateAsBuffer() {
        auto buffer = std::make_shared<Buffer>(PASS_N * sizeof(int64));
        std::copy((unsigned char *) mImpl->pubKey, ((unsigned char *) mImpl->pubKey) + PASS_N * sizeof(int64),
                  buffer->begin());
        return buffer;
      }

      bool PublicKey::importPrivate(const uint8_t *data, int size) {
        if (size != PASS_N * sizeof(int64)) {
          throw Error("PublicKey data size not match, require " + std::to_string(PASS_N * sizeof(int64) + HASH_BYTES) +
                      ", but input " + std::to_string(size));
        }
        std::copy(data, data + size, (unsigned char *) mImpl->pubKey);
        return true;
      }
    }
  }
}