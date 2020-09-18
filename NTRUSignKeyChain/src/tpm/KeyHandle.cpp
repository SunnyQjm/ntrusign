//
// Created by sunny on 2020/9/16.
//

#include "KeyHandle.h"

namespace ndn {
  namespace security {
    namespace ntru {
      ConstBufferPtr KeyHandle::sign(const uint8_t *buf, size_t size) const {
        return doSign(buf, size);
      }

      ConstBufferPtr KeyHandle::derivePublicKey() const {
        return doDerivePublicKey();
      }

      void KeyHandle::setKeyName(const Name &keyName) {
        this->mKeyName = keyName;
      }

      Name KeyHandle::getKeyName() const {
        return this->mKeyName;
      }
    }
  }
}