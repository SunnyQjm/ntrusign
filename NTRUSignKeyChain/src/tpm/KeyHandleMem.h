//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_KEYHANDLEMEM_H
#define NTRUSIGN_KEYHANDLEMEM_H

#include "KeyHandle.h"
#include "../PrivateKey.h"

namespace ndn {
  namespace security {
    namespace ntru {
      class KeyHandleMem : public KeyHandle {
      public:
        explicit KeyHandleMem(shared_ptr<PrivateKey> key);

      private:
        ConstBufferPtr
        doSign(const uint8_t *buf, size_t size) const;

        ConstBufferPtr
        doDerivePublicKey() const;

      private:
        shared_ptr<PrivateKey> mKey;
      };
    }
  }
}


#endif //NTRUSIGN_KEYHANDLEMEM_H
