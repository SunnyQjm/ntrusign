//
// Created by sunny on 2020/9/16.
//

#include "BackEnd.h"
#include "ndn-cxx/security/transform/buffer-source.hpp"
#include "ndn-cxx/security/transform/digest-filter.hpp"
#include "ndn-cxx/security/transform/stream-sink.hpp"
#include "ndn-cxx/encoding/buffer-stream.hpp"
#include "ndn-cxx/util/random.hpp"
#include "../common.h"

namespace ndn {
  namespace security {
    namespace ntru {
      bool BackEnd::hasKey(const Name &keyName) {
        return doHasKey(keyName);
      }

      unique_ptr<KeyHandle> BackEnd::getKeyHandle(const Name &keyName) const {
        return doGetKeyHandle(keyName);
      }

      unique_ptr<KeyHandle> BackEnd::createKey(const Name &identifyName) {
        return doCreateKey(identifyName);
      }

      void BackEnd::deleteKey(const Name &keyName) {
        doDeleteKey(keyName);
      }

      ConstBufferPtr BackEnd::exportKey(const Name &keyName) {
        if (!hasKey(keyName)) {
          NDN_THROW(Error("Key `" + keyName.toUri() + "` does not exist"));
        }
        return doExportKey(keyName);
      }

      void BackEnd::importKey(const Name &keyName, const uint8_t *data, size_t len) {
        if (hasKey(keyName)) {
          NDN_THROW(Error("Key `" + keyName.toUri() + "` already exists"));
        }
        doImportKey(keyName, data, len);
      }

      void BackEnd::setKeyName(KeyHandle &keyHandle, const Name &identityName) {
        name::Component keyId;

        using namespace ndn::security::transform;
        OBufferStream os;
        bufferSource(*keyHandle.derivePublicKey()) >>
                                                   digestFilter(DigestAlgorithm::SHA256) >>
                                                   streamSink(os);
        keyId = name::Component(os.buf());

        keyHandle.setKeyName(constructKeyName(identityName, keyId));
      }
    }
  }
}