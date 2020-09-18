#include <iostream>
//#include "PrivateKey.h"
//#include "PublicKey.h"
#include "utils/NTRUSignUtil.h"
#include <ndn-cxx/security/transform/private-key.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/verification-helpers.hpp>
#include <ndn-cxx/face.hpp>

using namespace std;
using namespace ndn::security::ntru;
using namespace ndn::security::transform;
using namespace ndn::security::v2;

int main() {
  NTRUSignUtil::init();
//  auto privateKey = PrivateKey::generateNTRUKey();
//  auto publicKey = PublicKey::derivePublicKey(*privateKey);
//  PrivateKey privateKey1;
//  auto privateKeyBuffer = privateKey->exportPrivateAsBuffer();
//  privateKey1.import(privateKeyBuffer->data(), privateKeyBuffer->size());
//  PublicKey publicKey1;
//  auto publicKeyBuffer = publicKey->exportPublicKeyAsBuffer();
//  publicKey1.import(publicKeyBuffer->data(), publicKeyBuffer->size());
//
//  std::string msg = "asdfasdfsadf";
//  auto signature = privateKey1.sign(msg);
//  auto signatureBuffer = signature->exportPrivateAsBuffer();
//  Signature signature1;
//  signature1.import(signatureBuffer->data(), signatureBuffer->size());
//  cout << publicKey1.verify(msg, signature1) << endl;

  auto privateKey = ndn::security::transform::PrivateKey::generateNTRUKey();
  auto publicKeyBuffer = privateKey->deriveNTRUPublicKey();
  ndn::security::transform::PublicKey publicKey;
  publicKey.loadNTRUKey(publicKeyBuffer->data(), publicKeyBuffer->size());
  std::string msg = "sdafasfsadf";
  auto signature = privateKey->ntruSign(reinterpret_cast<const uint8_t *>(msg.c_str()), msg.size());
  auto result = publicKey.ntruVerify(reinterpret_cast<const uint8_t *>(msg.c_str()), msg.size(), signature);
  cout << "verify result: " << result << endl;
  cout << (privateKey->getKeyType() == ndn::KeyType::NTRU) << ", " << (publicKey.getKeyType() == ndn::KeyType::NTRU) << endl;

  KeyChain keyChain;
  ndn::SimplePublicKeyParams<ndn::detail::NTRUParamsInfo> keyParams;
  auto identity = keyChain.createIdentity(ndn::Name("/testntru4"), keyParams);
  keyChain.setDefaultIdentity(identity);
  ndn::Interest interest("/testntru4");
  keyChain.sign(interest);
  bool verifyResult = ndn::security::verifySignature(interest, keyChain.getPib().getDefaultIdentity().getDefaultKey());
  cout << "Interest packet verify result: " << verifyResult << endl;
  using namespace ndn;
//  ndn::Face face;
//  face.expressInterest(interest, [](const Interest&, const Data&){
//
//  }, [](const Interest&, const lp::Nack&){
//
//  }, [](const Interest&){
//
//  });
//  face.processEvents();
  NTRUSignUtil::clean();
}