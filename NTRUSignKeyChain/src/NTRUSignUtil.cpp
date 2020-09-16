//
// Created by sunny on 2020/9/15.
//

#include "NTRUSignUtil.h"

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

      NTRUSignUtil::NTRUSignUtil(uint64 passN) {

      }

      void NTRUSignUtil::init() {
        init_fast_prng();
        if (ntt_setup() == -1) {
          throw Error("ERROR: Could not initialize FFTW. Bad wisdom?");
        }
      }

      void NTRUSignUtil::clean() {
        ntt_cleanup();
      }
    }
  }
}
