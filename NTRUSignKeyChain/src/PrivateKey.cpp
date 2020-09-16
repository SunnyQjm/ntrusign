//
// Created by sunny on 2020/9/16.
//

#include "PrivateKey.h"

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
      inline int doSign(unsigned char *h, int64 *z, const int64 *key,
                        const unsigned char *message, const int msglen) {
        return sign(h, z, key, message, msglen);
      }

      /////////////////////////////////////////////////////////////////////////////////////////
      //// Private Key
      /////////////////////////////////////////////////////////////////////////////////////////
      class PrivateKey::Impl {
      public:
        Impl() noexcept = default;

        ~Impl() = default;

      public:
        int64 key[PASS_N]{};
        unsigned char h[HASH_BYTES]{};
      };

      PrivateKey::PrivateKey() : mImpl(std::make_unique<Impl>()) {

      }

      PrivateKey::~PrivateKey() {

      }

      std::unique_ptr<PrivateKey> PrivateKey::generateNTRUKey() {
        auto privateKey = std::make_unique<PrivateKey>();

        // generate key
        gen_key(privateKey->mImpl->key);

        // generate h
        crypto_hash_sha512(privateKey->mImpl->h, (unsigned char *) privateKey->mImpl->key, sizeof(int64) * PASS_N);

        return privateKey;
      }

      std::unique_ptr<Signature> PrivateKey::sign(const unsigned char *message, const int messageLen) {
        auto signature = std::make_unique<Signature>();
        doSign(this->mImpl->h, signature->data, this->mImpl->key, message, messageLen);
        std::copy(std::begin(mImpl->h), std::end(mImpl->h), std::begin(signature->h));
        return signature;
      }

      std::unique_ptr<Signature> PrivateKey::sign(const char *message, int messageLen) {
        return sign(reinterpret_cast<const unsigned char *>(message), messageLen);
      }

      std::unique_ptr<Signature> PrivateKey::sign(const std::string &msg) {
        return sign(msg.c_str(), msg.size());
      }

      std::unique_ptr<std::vector<int64>> PrivateKey::derivePublicKey() const {
        auto buffer = std::make_unique<std::vector<int64>>(PASS_N);
        gen_pubkey(buffer->data(), mImpl->key);
        return buffer;
      }

      ConstBufferPtr PrivateKey::exportPrivateAsBuffer() {
        auto buffer = std::make_shared<Buffer>(PASS_N * sizeof(int64) + HASH_BYTES);

        std::copy((unsigned char *) mImpl->key, ((unsigned char *) mImpl->key) + PASS_N * sizeof(int64),
                  buffer->begin());
        std::copy(std::begin(mImpl->h), std::end(mImpl->h), buffer->begin() + PASS_N * sizeof(int64));
        return buffer;
      }

      bool PrivateKey::importPrivate(const uint8_t *data, int size) {
        if (size != PASS_N * sizeof(int64) + HASH_BYTES) {
          throw Error("PrivateKey data size not match, require " + std::to_string(PASS_N * sizeof(int64) + HASH_BYTES) +
                      ", but input " + std::to_string(size));
        }
        std::copy(data, data + PASS_N * sizeof(int64), (unsigned char *) mImpl->key);
        std::copy(data + PASS_N * sizeof(int64), data + size, mImpl->h);
        return true;
      }

    }
  }
}
