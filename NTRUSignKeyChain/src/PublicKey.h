//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_PUBLICKEY_H
#define NTRUSIGN_PUBLICKEY_H

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

#include "Signature.h"
#include "PrivateKey.h"

namespace ndn {
  namespace security {
    namespace ntru {
      class PublicKey {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        PublicKey();

        ~PublicKey();

        // verify method
        bool verify(const unsigned char *message, int messageLen, const Signature& signature);
        bool verify(const char *message, int messageLen, const Signature& signature);
        bool verify(const std::string &msg, const Signature& signature);

        // export and import
        ConstBufferPtr exportPrivateAsBuffer();

        bool import(const uint8_t *data, int size);
      public:
        static std::unique_ptr<PublicKey> derivePublicKey(const PrivateKey &privateKey);

      private:
        class Impl;

        const std::unique_ptr<Impl> mImpl;
      };
    }
  }
}


#endif //NTRUSIGN_PUBLICKEY_H
