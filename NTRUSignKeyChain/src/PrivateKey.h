//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_PRIVATEKEY_H
#define NTRUSIGN_PRIVATEKEY_H

#include <cstdint>
#include <memory>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif
#include <ntrusign/constants.h>
#include <ntrusign/pass_types.h>
#include <ntrusign/hash.h>
#include <ntrusign/ntt.h>
#include <ntrusign/pass.h>
#ifdef __cplusplus
}
#endif

#include "Buffer.h"
#include "Signature.h"

namespace ndn {
  namespace security {
    namespace ntru {
      class PrivateKey {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        PrivateKey();

        ~PrivateKey();

        std::unique_ptr<std::vector<int64>> derivePublicKey() const;

        // sign method
        std::unique_ptr<Signature> sign(const unsigned char *message, int messageLen);

        std::unique_ptr<Signature> sign(const char *message, int messageLen);

        std::unique_ptr<Signature> sign(const std::string &msg);

        // export and import
        ConstBufferPtr exportPrivateAsBuffer();

        bool importPrivate(const uint8_t *data, int size);
      public:
        static std::unique_ptr<PrivateKey> generateNTRUKey();

      private:
        class Impl;

        friend class PublicKey;

        const std::unique_ptr<Impl> mImpl;
      };
    }
  }
}

#endif //NTRUSIGN_PRIVATEKEY_H
