//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_SIGNATURE_H
#define NTRUSIGN_SIGNATURE_H

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

      public:
        int64 data[PASS_N]{};
        unsigned char h[HASH_BYTES]{};
      };
    }
  }
}


#endif //NTRUSIGN_SIGNATURE_H
