use bytes::Bytes;
use der::{
    Decode, Encode,
    asn1::{BitString, GeneralizedTime, Null, OctetString},
};
use h3x::{Endpoint, Error};
use rcgen::SigningKey;
use ring::digest;
use x509_ocsp::{
    BasicOcspResponse, CertId, CertStatus, OcspResponse, ResponderId, ResponseData, RevokedInfo,
    SingleResponse,
};
use x509_parser::prelude::{FromDer, X509Certificate};

#[test]
fn certificate_name_validation_is_domain_independent() {
    for name in ["dhttp.net", "peer.dhttp.net", "genmeta.net"] {
        let generated = rcgen::generate_simple_self_signed(vec![name.into()]).unwrap();
        let certs = vec![generated.cert.der().clone()];
        assert!(
            Endpoint::new(
                name,
                certs.clone(),
                rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                    .into(),
                None,
            )
            .is_ok()
        );
        assert!(h3x::RemoteAuthority::from_authenticated(name, certs.clone()).is_ok());
        assert!(h3x::RemoteAuthority::from_authenticated("other.example", certs).is_err());
    }
}

#[test]
fn endpoint_validates_certificate_and_signed_ocsp() {
    let mut params = rcgen::CertificateParams::new(vec!["test.example".into()]).unwrap();
    // 128 requires a DER sign-padding zero; random serials only rarely exercise it.
    params.serial_number = Some(128u64.into());
    let signing_key = rcgen::KeyPair::generate().unwrap();
    let generated = rcgen::CertifiedKey {
        cert: params.self_signed(&signing_key).unwrap(),
        signing_key,
    };
    let cert = generated.cert.der();
    let (_, parsed) = X509Certificate::from_der(cert).unwrap();
    let make = |name: &str, staple: Option<Vec<u8>>| {
        Endpoint::new(
            name,
            vec![cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
            staple.map(Bytes::from),
        )
    };
    assert_eq!(make("test.example.", None).unwrap().name(), "test.example");
    assert!(make("other.example", None).is_err());
    assert!(make("*.example", None).is_err());
    assert!(make("test.example", Some(vec![])).is_err());
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let time = |seconds| {
        GeneralizedTime::from_unix_duration(std::time::Duration::from_secs(seconds))
            .unwrap()
            .into()
    };
    let hash = |data: &[u8]| {
        OctetString::new(digest::digest(&digest::SHA1_FOR_LEGACY_USE_ONLY, data).as_ref()).unwrap()
    };
    let mut basic = BasicOcspResponse {
        tbs_response_data: ResponseData {
            version: Default::default(),
            responder_id: ResponderId::ByKey(hash(&parsed.public_key().subject_public_key.data)),
            produced_at: time(now),
            responses: vec![SingleResponse {
                cert_id: CertId {
                    hash_algorithm: der::Decode::from_der(&[0x30, 7, 6, 5, 0x2b, 0x0e, 3, 2, 0x1a])
                        .unwrap(),
                    issuer_name_hash: hash(parsed.subject().as_raw()),
                    issuer_key_hash: hash(&parsed.public_key().subject_public_key.data),
                    serial_number: der::Decode::from_der(&{
                        let mut serial = vec![2, parsed.raw_serial().len() as u8];
                        serial.extend(parsed.raw_serial());
                        serial
                    })
                    .unwrap(),
                },
                cert_status: CertStatus::Good(Null),
                this_update: time(now - 60),
                next_update: Some(time(now + 3600)),
                single_extensions: None,
            }],
            response_extensions: None,
        },
        signature_algorithm: der::Decode::from_der(&[
            0x30, 10, 6, 8, 0x2a, 0x86, 0x48, 0xce, 0x3d, 4, 3, 2,
        ])
        .unwrap(),
        signature: BitString::from_bytes(&[]).unwrap(),
        certs: None,
    };
    let encode_with = |mut basic: BasicOcspResponse, key: &rcgen::KeyPair| {
        basic.signature = BitString::from_bytes(
            &key.sign(&basic.tbs_response_data.to_der().unwrap())
                .unwrap(),
        )
        .unwrap();
        OcspResponse::successful(basic).unwrap().to_der().unwrap()
    };
    let encode = |basic| encode_with(basic, &generated.signing_key);
    let good = encode(basic.clone());
    let result = make("test.example", Some(good.clone()));
    assert!(
        result.is_ok(),
        "valid OCSP failed: {result:?}; serial={:x?}",
        parsed.raw_serial()
    );
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(make("test.example", Some(trailing)).is_err());
    let mut tampered = good.clone();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(matches!(
        make("test.example", Some(tampered)),
        Err(Error::InvalidEndpoint { .. })
    ));
    basic.tbs_response_data.responder_id =
        ResponderId::ByName(Decode::from_der(parsed.subject().as_raw()).unwrap());
    assert!(make("test.example", Some(encode(basic.clone()))).is_ok());
    let good_basic = basic.clone();
    basic.tbs_response_data.responses[0].cert_status = CertStatus::Revoked(RevokedInfo {
        revocation_time: time(now - 60),
        revocation_reason: None,
    });
    assert!(matches!(
        make("test.example", Some(encode(basic.clone()))),
        Err(Error::CertificateRevoked)
    ));
    basic.tbs_response_data.responses[0].cert_status = CertStatus::Unknown(Null);
    assert!(matches!(
        make("test.example", Some(encode(basic))),
        Err(Error::InvalidEndpoint { .. })
    ));
    for change in 0..7 {
        let mut basic = good_basic.clone();
        let tbs = &mut basic.tbs_response_data;
        match change {
            0 => tbs.responses[0].next_update = Some(time(now - 1)),
            1 => tbs.responses[0].cert_id.issuer_name_hash = OctetString::new(vec![0; 20]).unwrap(),
            2 => tbs.responses.push(tbs.responses[0].clone()),
            3 => tbs.produced_at = time(now + 600),
            4 => tbs.responses[0].this_update = time(now + 600),
            5 => tbs.responses[0].cert_id.issuer_key_hash = OctetString::new(vec![0; 20]).unwrap(),
            _ => tbs.responses[0].cert_id.serial_number = 123u32.into(),
        }
        assert!(
            matches!(
                make("test.example", Some(encode(basic))),
                Err(Error::InvalidEndpoint { .. })
            ),
            "case {change}"
        );
    }
    for authorized in [false, true] {
        let key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec![]).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "OCSP responder");
        if authorized {
            params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::OcspSigning];
        }
        let issuer_params = rcgen::CertificateParams::new(vec!["test.example".into()]).unwrap();
        let issuer = rcgen::Issuer::from_params(&issuer_params, &generated.signing_key);
        let delegate = params.signed_by(&key, &issuer).unwrap();
        let (_, delegate_parsed) = X509Certificate::from_der(delegate.der()).unwrap();
        let mut basic = good_basic.clone();
        basic.tbs_response_data.responder_id =
            ResponderId::ByKey(hash(&delegate_parsed.public_key().subject_public_key.data));
        basic.certs = Some(vec![Decode::from_der(delegate.der()).unwrap()]);
        assert_eq!(
            make("test.example", Some(encode_with(basic, &key))).is_ok(),
            authorized
        );
    }
    let mut critical = good_basic.clone();
    critical.tbs_response_data.response_extensions = Some(vec![
        Decode::from_der(&[0x30, 10, 6, 3, 0x2a, 3, 4, 1, 1, 0xff, 4, 0]).unwrap(),
    ]);
    assert!(make("test.example", Some(encode(critical))).is_err());
    let mut basic = good_basic;
    basic.tbs_response_data.responses[0].next_update = None;
    assert!(make("test.example", Some(encode(basic.clone()))).is_ok());
    basic.tbs_response_data.responses[0].this_update = time(now - 86_401);
    assert!(make("test.example", Some(encode(basic))).is_err());
    let other = rcgen::generate_simple_self_signed(vec!["test.example".into()]).unwrap();
    assert!(
        Endpoint::new(
            "test.example",
            vec![cert.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(other.signing_key.serialize_der()).into(),
            None
        )
        .is_err()
    );
    let mut params = rcgen::CertificateParams::new(vec!["test.example".into()]).unwrap();
    params.not_after = rcgen::date_time_ymd(2000, 1, 1);
    let expired = params.self_signed(&generated.signing_key).unwrap();
    assert!(
        Endpoint::new(
            "test.example",
            vec![expired.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(generated.signing_key.serialize_der())
                .into(),
            None
        )
        .is_err()
    );
}
