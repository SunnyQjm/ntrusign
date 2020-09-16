#include <iostream>
#include "PrivateKey.h"
#include "PublicKey.h"
#include "utils/NTRUSignUtil.h"

using namespace std;
using namespace ndn::security::ntru;

int main() {
  NTRUSignUtil::init();
  auto privateKey = PrivateKey::generateNTRUKey();
  auto publicKey = PublicKey::derivePublicKey(*privateKey);

  PrivateKey privateKey1;
  auto privateKeyBuffer = privateKey->exportPrivateAsBuffer();
  privateKey1.import(privateKeyBuffer->data(), privateKeyBuffer->size());
  PublicKey publicKey1;
  auto publicKeyBuffer = publicKey->exportPrivateAsBuffer();
  publicKey1.import(publicKeyBuffer->data(), publicKeyBuffer->size());

  std::string msg = "asdfasdfsadf";
  auto signature = privateKey1.sign(msg);
  auto signatureBuffer = signature->exportPrivateAsBuffer();
  Signature signature1;
  signature1.import(signatureBuffer->data(), signatureBuffer->size());
  cout << publicKey1.verify(msg, signature1) << endl;

  NTRUSignUtil::clean();
}