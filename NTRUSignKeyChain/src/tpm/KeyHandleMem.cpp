//
// Created by sunny on 2020/9/16.
//

#include "KeyHandleMem.h"

namespace ndn {
  namespace security {
    namespace ntru {
      KeyHandleMem::KeyHandleMem(shared_ptr<PrivateKey> key) : mKey(std::move(key)) {

      }

      ConstBufferPtr KeyHandleMem::doSign(const uint8_t *buf, size_t size) const {
        return mKey->sign(buf, size)->exportPrivateAsBuffer();
      }

      ConstBufferPtr KeyHandleMem::doDerivePublicKey() const {
        return mKey->derivePublicKey();
      }
    }
  }
}