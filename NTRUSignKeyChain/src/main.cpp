#include <iostream>
#include "PrivateKey.h"
#include "PublicKey.h"
#include "NTRUSignUtil.h"

using namespace std;
using namespace ndn::security::ntru;

int main() {
  NTRUSignUtil::init();
  auto privateKey = PrivateKey::generateNTRUKey();
  auto publicKey = PublicKey::derivePublicKey(*privateKey);

  PrivateKey privateKey1;
  auto privateKeyBuffer = privateKey->exportPrivateAsBuffer();
  privateKey1.importPrivate(privateKeyBuffer->data(), privateKeyBuffer->size());
  PublicKey publicKey1;
  auto publicKeyBuffer = publicKey->exportPrivateAsBuffer();
  publicKey1.importPrivate(publicKeyBuffer->data(), publicKeyBuffer->size());

  std::string msg = "asdfasdfsadf";
  auto signature = privateKey1.sign(msg);
  cout << publicKey1.verify(msg, *signature) << endl;

  NTRUSignUtil::clean();
}