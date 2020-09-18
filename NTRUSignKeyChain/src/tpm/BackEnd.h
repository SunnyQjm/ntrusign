//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_BACKEND_H
#define NTRUSIGN_BACKEND_H

#include "ndn-cxx/security/key-params.hpp"
#include "ndn-cxx/encoding/buffer.hpp"
#include "ndn-cxx/name.hpp"
#include "KeyHandle.h"

namespace ndn {
  namespace security {
    namespace ntru {
      class BackEnd {
      public:
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        virtual ~BackEnd();

      public: // key management
        bool hasKey(const Name &keyName);

        unique_ptr<KeyHandle> getKeyHandle(const Name &keyName) const;

        unique_ptr<KeyHandle> createKey(const Name &identifyName);

        void deleteKey(const Name &keyName);

        ConstBufferPtr exportKey(const Name &keyName);

        void importKey(const Name &keyName, const uint8_t *data, size_t len);

      protected:
        static void setKeyName(KeyHandle &keyHandle, const Name &identityName);

      private:
        virtual bool doHasKey(const Name &keyName) = 0;

        virtual unique_ptr<KeyHandle> doGetKeyHandle(const Name &keyName) const = 0;

        virtual unique_ptr<KeyHandle> doCreateKey(const Name &identifyName) = 0;

        virtual void doDeleteKey(const Name &keyName) = 0;

        virtual ConstBufferPtr doExportKey(const Name &keyName) = 0;

        virtual void doImportKey(const Name &keyName, const uint8_t *data, size_t len) = 0;
      };
    }
  }
}


#endif //NTRUSIGN_BACKEND_H
