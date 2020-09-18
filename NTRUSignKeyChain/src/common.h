//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_COMMON_H
#define NTRUSIGN_COMMON_H

#include "ndn-cxx/security/v2/certificate.hpp"

namespace ndn {
  namespace security {
    namespace ntru {
      Name
      constructKeyName(const Name& identity, const name::Component& keyId)
      {
        Name keyName = identity;
        keyName
            .append(v2::Certificate::KEY_COMPONENT)
            .append(keyId);
        return keyName;
      }
    }
  }
}
#endif //NTRUSIGN_COMMON_H
