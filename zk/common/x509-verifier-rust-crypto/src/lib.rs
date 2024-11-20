pub mod constants;
pub mod sig;

// re-exports
pub use p256;
pub use p384;
pub use rsa;
pub use sha2;
pub use x509_parser;

use constants::*;
use sig::*;

use oid::ObjectIdentifier;
use x509_parser::oid_registry::asn1_rs::Any;
use x509_parser::prelude::*;

pub fn verify_x509_chain(cert_chain: &[X509Certificate]) -> bool {
    for (i, cert) in cert_chain.iter().enumerate() {
        let subject = cert;
        let issuer: Option<&X509Certificate>;
        if cert == cert_chain.last().unwrap() {
            issuer = None;
        } else {
            issuer = Some(&cert_chain[i + 1]);
        }

        let verified = verify_cert_issuer(subject, issuer);
        if !verified {
            return false;
        }
    }

    true
}

fn verify_cert_issuer(subject: &X509Certificate, issuer: Option<&X509Certificate>) -> bool {
    // the issuer param can be ommited,
    // if and only if it signs its own certificate, e.g. a root certificate
    let current_issuer: &X509Certificate;
    match issuer {
        Some(issuer_found) => current_issuer = issuer_found,
        None => current_issuer = subject,
    }

    let subject_sig_algo = subject.signature_algorithm.oid().to_id_string();

    let issuer_pub_key_info = current_issuer.public_key();
    let issuer_key_algo = issuer_pub_key_info.algorithm.oid().to_id_string();
    let issuer_key_val = issuer_pub_key_info.subject_public_key.as_ref();

    let subject_tbs = subject.tbs_certificate.as_ref();
    let subject_sig_val = subject.signature_value.as_ref();

    match issuer_key_algo.as_str() {
        EC_KEY_ALGO_OID => {
            // println!("EC Key");
            let issuer_key_param = issuer_pub_key_info.algorithm.parameters().unwrap();
            let param_oid = ObjectIdentifier::try_from(issuer_key_param.data).unwrap();
            let param_oid_string: String = (&param_oid).into();
            match param_oid_string.as_str() {
                EC_KEY_P256_PARAM_OID => {
                    // println!("P256");
                    if subject_sig_algo.eq(ECDSA_SHA256_OID) {
                        // println!("SHA256_ECDSA");
                        return verify_p256_sha256(subject_tbs, subject_sig_val, issuer_key_val);
                    }
                    panic!("Incompatible Sig Algo");
                }
                EC_KEY_P384_PARAM_OID => {
                    // println!("P384");
                    match subject_sig_algo.as_str() {
                        ECDSA_SHA256_OID => {
                            // println!("SHA256_ECDSA");
                            verify_p384_sha256(subject_tbs, subject_sig_val, issuer_key_val)
                        }
                        ECDSA_SHA384_OID => {
                            // println!("SHA384_ECDSA");
                            verify_p384_sha384(subject_tbs, subject_sig_val, issuer_key_val)
                        }
                        _ => {
                            panic!("Incompatible Sig Algo");
                        }
                    }
                }
                _ => {
                    panic!("Unknown key param");
                }
            }
        }
        RSA_PKCS1_V1_5_KEY_OID => {
            // println!("RSA Key");
            match subject_sig_algo.as_str() {
                SHA256_WITH_RSA_ENCRYPTION_OID => {
                    // println!("SHA256_RSA");
                    verify_pkcs1_rsa_sha256(subject_tbs, subject_sig_val, issuer_key_val)
                }
                RSASSA_PSS_OID => {
                    // println!("RSASSA_PSS");

                    let sig_algo_params = subject.signature_algorithm.parameters().unwrap();
                    let hash_algo = get_rsassa_pss_hash_algo(sig_algo_params);

                    match hash_algo {
                        SHA384_HASH_OID => verify_pss_pkcs1_mgf_rsa_sha384(
                            subject_tbs,
                            subject_sig_val,
                            issuer_key_val,
                        ),
                        _ => {
                            panic!("Hash algo for this sig is currently not supported");
                        }
                    }
                }
                _ => {
                    panic!("Unexpected sig algo");
                }
            }
        }
        _ => {
            panic!("Unknown key OID");
        }
    }
}

fn get_rsassa_pss_hash_algo<'a>(_sig_algo_params: &'a Any) -> &'a str {
    // TODO

    // println!("{:x?}", sig_algo_params.data);

    SHA384_HASH_OID
}

#[cfg(test)]
mod tests {
    use super::verify_x509_chain;
    use x509_parser::prelude::*;

    #[test]
    fn test_apple_ios_der_ecdsa() {
        let app_attest_leaf_der = hex::decode("308203153082029BA0030201020206018D6956E63B300A06082A8648CE3D040302304F3123302106035504030C1A4170706C6520417070204174746573746174696F6E204341203131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E6961301E170D3234303230313130323135395A170D3234303230343130323135395A3081913149304706035504030C4039663066313831346264383262303438396161626630356533316362393231373637643832623561666236633266303134653637653564653764386632646332311A3018060355040B0C114141412043657274696669636174696F6E31133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E69613059301306072A8648CE3D020106082A8648CE3D03010703420004B66593E9C15DC786C8364DD98597827DCAF7DD351DC91DB1ABB4B8881D7F4CE5A55D60A3FCDC708B5985914EEBDF6D91F229A7350420E88E8941DEFBF55E978DA382011E3082011A300C0603551D130101FF04023000300E0603551D0F0101FF0404030204F030819C06092A864886F76364080504818E30818BA40302010ABF893003020101BF893103020100BF893203020100BF893303020101BF89343B043943323248364B434738392E636F6D2E6175746F6D6174612E2D2D50524F445543542D4E414D452D726663313033346964656E7469666965722DA506040420736B73BF893603020105BF893703020100BF893903020100BF893A03020100BF893B03020100302606092A864886F76364080704193017BF8A7808040631352E382E31BF885007020500FFFFFFFF303306092A864886F76364080204263024A122042075FA238FDB27F80D8419C9E1407AF7B35643E2BB880761770A0DF33D250F5012300A06082A8648CE3D0403020368003065023100AAA32BB4C6CC3F902FB9F0976094217491BD3DEDFB7F36F15B5BD8EDC738C4603EDD8664C53FDB1849B436E7AA617E6D0230129FFF41EBB1BE87D1B3AE93B0EBCA721AE50DE809264506177870629DABE607187A5E8941C583ABEE410F776C4A322E").unwrap();
        let app_attest_ca_1_der = hex::decode("30820243308201C8A003020102021009BAC5E1BC401AD9D45395BC381A0854300A06082A8648CE3D04030330523126302406035504030C1D4170706C6520417070204174746573746174696F6E20526F6F7420434131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E6961301E170D3230303331383138333935355A170D3330303331333030303030305A304F3123302106035504030C1A4170706C6520417070204174746573746174696F6E204341203131133011060355040A0C0A4170706C6520496E632E3113301106035504080C0A43616C69666F726E69613076301006072A8648CE3D020106052B8104002203620004AE5B37A0774D79B2358F40E7D1F22626F1C25FEF17802DEAB3826A59874FF8D2AD1525789AA26604191248B63CB967069E98D363BD5E370FBFA08E329E8073A985E7746EA359A2F66F29DB32AF455E211658D567AF9E267EB2614DC21A66CE99A366306430120603551D130101FF040830060101FF020100301F0603551D23041830168014AC91105333BDBE6841FFA70CA9E5FAEAE5E58AA1301D0603551D0E041604143EE35D1C0419A9C9B431F88474D6E1E15772E39B300E0603551D0F0101FF040403020106300A06082A8648CE3D0403030369003066023100BBBE888D738D0502CFBCFD666D09575035BCD6872C3F8430492629EDD1F914E879991C9AE8B5AEF8D3A85433F7B60D06023100AB38EDD0CC81ED00A452C3BA44F993636553FECC297F2EB4DF9F5EBE5A4ACAB6995C4B820DF904386F7807BB589439B7").unwrap();
        let app_attest_root_ca_der= hex::decode("30820221308201a7a00302010202100bf3be0ef1cdd2e0fb8c6e721f621798300a06082a8648ce3d04030330523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e6961301e170d3230303331383138333235335a170d3435303331353030303030305a30523126302406035504030c1d4170706c6520417070204174746573746174696f6e20526f6f7420434131133011060355040a0c0a4170706c6520496e632e3113301106035504080c0a43616c69666f726e69613076301006072a8648ce3d020106052b81040022036200044531e198b5b4ec04da1502045704ed4f877272d76135b26116cfc88b615d0a000719ba69858dfe77caa3b839e020ddd656141404702831e43f70b88fd6c394b608ea2bd6ae61e9f598c12f46af52937266e57f14eb61fec530f7144f53812e35a3423040300f0603551d130101ff040530030101ff301d0603551d0e04160414ac91105333bdbe6841ffa70ca9e5faeae5e58aa1300e0603551d0f0101ff040403020106300a06082a8648ce3d040303036800306502304201469c1cafb2255ba532b04a06b490fd1ef047834b8fac4264ef6fbbe7e773b9f8545781e2e1a49d3acac0b93eb3b2023100a79538c43804825945ec49f755c13789ec5966d29e627a6ab628d5a3216b696548c9dfdd81a9e6addb82d5b993046c03").unwrap();

        let cert_chain_der = [
            app_attest_leaf_der.as_slice(),
            app_attest_ca_1_der.as_slice(),
            app_attest_root_ca_der.as_slice(),
        ];

        let mut cert_chain_vec: Vec<X509Certificate> = Vec::with_capacity(3);

        for cert_der in cert_chain_der {
            match parse_x509_certificate(cert_der) {
                Ok((_, cert)) => cert_chain_vec.push(cert),
                Err(e) => panic!("Error parsing certificate: {:?}", e),
            }
        }

        assert!(verify_x509_chain(&cert_chain_vec));
    }

    #[test]
    fn test_android_pem_chain() {
        let pem_path: &str = "./samples/android-attestation.pem";
        let pem_chain_data = std::fs::read(pem_path).expect("PEM file not found");
        let der_chain = pem_to_der(&pem_chain_data);

        let mut cert_chain_vec: Vec<X509Certificate> = Vec::with_capacity(der_chain.len());

        for der in der_chain.iter() {
            match parse_x509_certificate(der) {
                Ok((_, cert)) => cert_chain_vec.push(cert),
                Err(e) => panic!("Error parsing certificate: {:?}", e),
            }
        }

        assert!(verify_x509_chain(&cert_chain_vec));
    }

    #[test]
    fn test_vlek_ca_pem_chain() {
        let pem_path: &str = "./samples/vlek_milan_cert_chain.pem";
        let pem_chain_data = std::fs::read(pem_path).expect("PEM file not found");
        let der_chain = pem_to_der(&pem_chain_data);

        let mut cert_chain_vec: Vec<X509Certificate> = Vec::with_capacity(der_chain.len());

        for der in der_chain.iter() {
            match parse_x509_certificate(der) {
                Ok((_, cert)) => cert_chain_vec.push(cert),
                Err(e) => panic!("Error parsing certificate: {:?}", e),
            }
        }

        assert!(verify_x509_chain(&cert_chain_vec));
    }

    #[test]
    fn test_vcek_chain() {
        let ca_pem_path: &str = "./samples/vcek_milan_cert_chain.pem";
        let ca_pem_chain_data = std::fs::read(ca_pem_path).expect("PEM file not found");

        let vcek_der_path: &str = "./samples/vcek.der";
        let vcek_der = std::fs::read(vcek_der_path).expect("VCEK DER not found");

        println!("{}", hex::encode(&vcek_der));

        let der_ca_chain = pem_to_der(&ca_pem_chain_data);
        let mut der_chain: Vec<Vec<u8>> = Vec::with_capacity(der_ca_chain.len() + 1);

        der_chain.push(vcek_der);
        der_chain.extend(der_ca_chain);

        let mut cert_chain_vec: Vec<X509Certificate> = Vec::with_capacity(der_chain.len());

        for der in der_chain.iter() {
            match parse_x509_certificate(der) {
                Ok((_, cert)) => cert_chain_vec.push(cert),
                Err(e) => panic!("Error parsing certificate: {:?}", e),
            }
        }

        assert!(verify_x509_chain(&cert_chain_vec));
    }

    // Helper function

    // PEM chain to DER-encoded bytes conversion
    // Provide PEM data directly to this function call
    fn pem_to_der(pem_chain: &[u8]) -> Vec<Vec<u8>> {
        let mut der_chain: Vec<Vec<u8>> = Vec::new();

        for pem in Pem::iter_from_buffer(pem_chain) {
            let current_pem_content = pem.unwrap().contents;
            der_chain.push(current_pem_content);
        }

        der_chain
    }
}
