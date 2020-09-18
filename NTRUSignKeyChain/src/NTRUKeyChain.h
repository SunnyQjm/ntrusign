//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_NTRUKEYCHAIN_H
#define NTRUSIGN_NTRUKEYCHAIN_H

#include <ndn-cxx/face.hpp>
#include "PrivateKey.h"
#include "PublicKey.h"

namespace ndn {
  namespace security {
    namespace ntru {
      using namespace ndn;
      using namespace ndn::security::ntru;

      class NTRUKeyChain {
        NTRUKeyChain();

      public:
        void sign(Data &data);

        void sign(Interest &interest);

        void verify(Interest &interest);

        void verify(Data &data);

      public:

      private:
        PrivateKey privateKey;
        PublicKey publicKey;
      };
    }
  }
}

#endif //NTRUSIGN_NTRUKEYCHAIN_H
