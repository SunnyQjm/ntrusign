//
// Created by sunny on 2020/9/15.
//

#ifndef NTRUSIGNLIB_NTRUSIGNUTIL_H
#define NTRUSIGNLIB_NTRUSIGNUTIL_H


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
      class PrivateKey;

      class PublicKey;

      class Signature;

      class NTRUSignUtil {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };
      public:
        explicit NTRUSignUtil(uint64 passN);

      public:
        static void init();
        static void clean();
      };
    }
  }
}

#endif //NTRUSIGNLIB_NTRUSIGNUTIL_H
