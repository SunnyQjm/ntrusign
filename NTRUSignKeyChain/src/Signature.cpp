//
// Created by sunny on 2020/9/16.
//

#include "Signature.h"

ConstBufferPtr ndn::security::ntru::Signature::exportPrivateAsBuffer() {
  auto buffer = std::make_shared<Buffer>(PASS_N * sizeof(int64) + HASH_BYTES);

  std::copy((unsigned char *) data, ((unsigned char *) data) + PASS_N * sizeof(int64),
            buffer->begin());
  std::copy(std::begin(h), std::end(h), buffer->begin() + PASS_N * sizeof(int64));
  return buffer;
}

bool ndn::security::ntru::Signature::import(const uint8_t *data, int size) {
  if (size != PASS_N * sizeof(int64) + HASH_BYTES) {
    throw Error("PrivateKey data size not match, require " + std::to_string(PASS_N * sizeof(int64) + HASH_BYTES) +
                ", but input " + std::to_string(size));
  }
  std::copy(data, data + PASS_N * sizeof(int64), (unsigned char *) this->data);
  std::copy(data + PASS_N * sizeof(int64), data + size, this->h);
  return true;
}
