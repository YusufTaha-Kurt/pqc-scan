use openssl::ec::EcGroup;
use openssl::hash::MessageDigest;
use openssl::nid::Nid;
use openssl::rsa::Rsa;
use openssl::symm::Cipher;

fn keys<'a>(input: &'a str) -> &'a str {
    let legacy = Rsa::generate(1024).unwrap();
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap();
    let digest = MessageDigest::sha1();
    let cipher = Cipher::des_ede3_cbc();
    let modern = rsa::RsaPrivateKey::new(&mut rng, 3072).unwrap();
    // let old = md5::compute(input);  (commented out after a lifetime 'a)
    let signing = p256::ecdsa::SigningKey::random(&mut rng);
    let kem = ml_kem::MlKem768::generate(&mut rng);
    input
}
