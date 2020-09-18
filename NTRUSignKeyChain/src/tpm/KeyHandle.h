//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_KEYHANDLE_H
#define NTRUSIGN_KEYHANDLE_H


#include "ndn-cxx/name.hpp"
#include "ndn-cxx/security/security-common.hpp"

namespace ndn {
  namespace security {
    namespace ntru {
      class KeyHandle {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        virtual ~KeyHandle();

      public:
        ConstBufferPtr sign(const uint8_t *buf, size_t size) const;

        ConstBufferPtr derivePublicKey() const;

        void setKeyName(const Name &keyName);

        Name getKeyName() const;

      private:
        virtual ConstBufferPtr
        doSign(const uint8_t *buf, size_t size) const = 0;

        virtual ConstBufferPtr
        doDerivePublicKey() const = 0;

      private:
        Name mKeyName;
      };
    }
  }
}

#endif //NTRUSIGN_KEYHANDLE_H
