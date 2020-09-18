//
// Created by sunny on 2020/9/16.
//

#ifndef NTRUSIGN_TPM_H
#define NTRUSIGN_TPM_H

#include <cstdint>
#include <memory>
#include <vector>
#include <ndn-cxx/face.hpp>

namespace ndn {
  namespace security {
    namespace ntru {
      class Tpm {
        class Error : public std::runtime_error {
        public:
          using std::runtime_error::runtime_error;
        };

      public:
        Tpm();

        ~Tpm();

        bool hasKey(const Name &keyName) const;

        ConstBufferPtr getPublicKey(const Name &keyName) const;

        ConstBufferPtr sign(const uint8_t *buf, size_t size, const Name &keuName) const;

        Name createKey(const Name &identifyName);

        void deleteKey(const Name &name);

        ConstBufferPtr exportPrivateKey(const Name &keyName);

        void importPrivateKey(const Name &keyName, const uint8_t *data, size_t len);


      };
    }
  }
}
#endif //NTRUSIGN_TPM_H
