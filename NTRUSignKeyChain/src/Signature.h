//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_SIGNATURE_H
#define NTRUSIGN_SIGNATURE_H

#ifdef __cplusplus
extern "C" {
#endif
#include <ntrusign/constants.h>
#include <ntrusign/pass_types.h>
#include <ntrusign/hash.h>
#ifdef __cplusplus
}
#endif

#include "Buffer.h"

namespace ndn {
  namespace security {
    namespace ntru {
      class Signature {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        explicit Signature() noexcept = default;

        ~Signature() = default;

        // export and import
        ConstBufferPtr exportPrivateAsBuffer();

        bool import(const uint8_t *_data, int size);

      private:
        int64 data[PASS_N]{};
        unsigned char h[HASH_BYTES]{};
        friend class PrivateKey;
        friend class PublicKey;
      };
    }
  }
}


#endif //NTRUSIGN_SIGNATURE_H
