//! Staple validation policy; ASN.1 decoding is handled by x509-ocsp.

use der::{Decode, Encode, asn1::AnyRef};
use ring::digest;
use rustls::pki_types::CertificateDer;
use x509_ocsp::{BasicOcspResponse, CertStatus, OcspResponse, OcspResponseStatus, ResponderId};
use x509_parser::{
    der_parser::asn1_rs::BitString,
    prelude::{ASN1Time, FromDer, X509Certificate},
    x509::AlgorithmIdentifier,
};

use super::invalid;
use crate::Error;

pub(super) fn check(chain: &[CertificateDer<'_>], data: &[u8]) -> Result<(), Error> {
    if data.is_empty() || data.len() > 64 * 1024 {
        return Err(invalid("OCSP response exceeds its size limit"));
    }
    let leaf_der = chain
        .first()
        .ok_or_else(|| invalid("empty certificate chain"))?;
    let (_, leaf) = X509Certificate::from_der(leaf_der).map_err(invalid)?;
    let (_, issuer) =
        X509Certificate::from_der(chain.get(1).unwrap_or(leaf_der)).map_err(invalid)?;
    if leaf.issuer() != issuer.subject() {
        return Err(invalid("OCSP issuer is missing from the certificate chain"));
    }
    leaf.verify_signature(Some(issuer.public_key()))
        .map_err(invalid)?;

    let response = OcspResponse::from_der(data).map_err(invalid)?;
    if response.response_status != OcspResponseStatus::Successful {
        return Err(invalid(
            "OCSP responder did not return a successful response",
        ));
    }
    let bytes = response
        .response_bytes
        .ok_or_else(|| invalid("missing OCSP response"))?;
    if bytes.response_type.to_string() != "1.3.6.1.5.5.7.48.1.1" {
        return Err(invalid("unsupported OCSP response type"));
    }
    let basic = BasicOcspResponse::from_der(bytes.response.as_bytes()).map_err(invalid)?;
    let tbs = &basic.tbs_response_data;
    if tbs
        .response_extensions
        .iter()
        .flatten()
        .chain(
            tbs.responses
                .iter()
                .flat_map(|single| single.single_extensions.iter().flatten()),
        )
        .any(|extension| extension.critical)
    {
        return Err(invalid("unsupported critical OCSP extension"));
    }
    let now = ASN1Time::now().timestamp() as u64;
    let produced = tbs.produced_at.0.to_unix_duration().as_secs();
    if produced > now + 300 {
        return Err(invalid("OCSP response was produced in the future"));
    }
    let matches_responder = |cert: &X509Certificate<'_>| -> Result<bool, Error> {
        Ok(match &tbs.responder_id {
            ResponderId::ByName(name) => name.to_der().map_err(invalid)? == cert.subject().as_raw(),
            ResponderId::ByKey(hash) => {
                hash.as_bytes()
                    == digest::digest(
                        &digest::SHA1_FOR_LEGACY_USE_ONLY,
                        &cert.public_key().subject_public_key.data,
                    )
                    .as_ref()
            }
        })
    };
    let certificates = basic
        .certs
        .iter()
        .flatten()
        .map(|cert| cert.to_der().map_err(invalid))
        .collect::<Result<Vec<_>, _>>()?;
    let certificates = certificates
        .iter()
        .map(|der| {
            X509Certificate::from_der(der)
                .map(|(_, cert)| cert)
                .map_err(invalid)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let signer = if matches_responder(&issuer)? {
        &issuer
    } else {
        let signer = certificates
            .iter()
            .find(|cert| matches_responder(cert).unwrap_or(false))
            .ok_or_else(|| invalid("OCSP responder certificate is missing"))?;
        if signer.issuer() != issuer.subject() || !signer.validity().is_valid() {
            return Err(invalid(
                "OCSP responder is not an authorized issuer delegate",
            ));
        }
        signer
            .verify_signature(Some(issuer.public_key()))
            .map_err(invalid)?;
        if !signer
            .extended_key_usage()
            .map_err(invalid)?
            .is_some_and(|eku| eku.value.ocsp_signing)
        {
            return Err(invalid("responder certificate lacks OCSP signing usage"));
        }
        if signer
            .key_usage()
            .map_err(invalid)?
            .is_some_and(|usage| !usage.value.digital_signature())
        {
            return Err(invalid("responder certificate cannot sign"));
        }
        signer
    };
    // Verify the original signed bytes, without normalizing the decoded ResponseData.
    let sequence = AnyRef::from_der(bytes.response.as_bytes()).map_err(invalid)?;
    let mut reader = der::SliceReader::new(sequence.value()).map_err(invalid)?;
    let signed = AnyRef::decode(&mut reader)
        .map_err(invalid)?
        .to_der()
        .map_err(invalid)?;
    let algorithm_der = basic.signature_algorithm.to_der().map_err(invalid)?;
    let (_, algorithm) = AlgorithmIdentifier::from_der(&algorithm_der).map_err(invalid)?;
    let signature_der = basic.signature.to_der().map_err(invalid)?;
    let (_, signature) = BitString::from_der(&signature_der).map_err(invalid)?;
    if signature.unused_bits != 0 {
        return Err(invalid("invalid OCSP signature bit string"));
    }
    x509_parser::verify::verify_signature(signer.public_key(), &algorithm, &signature, &signed)
        .map_err(invalid)?;

    let leaf_serial = der::asn1::UintRef::new(leaf.raw_serial()).map_err(invalid)?;
    let mut matched = None;
    for single in &tbs.responses {
        let id = &single.cert_id;
        // x509-cert also accepts negative serials for compatibility; OCSP does not.
        let serial_der = id.serial_number.to_der().map_err(invalid)?;
        let serial = der::asn1::UintRef::from_der(&serial_der).map_err(invalid)?;
        let algorithm = match id.hash_algorithm.oid.to_string().as_str() {
            "1.3.14.3.2.26" => &digest::SHA1_FOR_LEGACY_USE_ONLY,
            "2.16.840.1.101.3.4.2.1" => &digest::SHA256,
            "2.16.840.1.101.3.4.2.2" => &digest::SHA384,
            "2.16.840.1.101.3.4.2.3" => &digest::SHA512,
            _ => return Err(invalid("unsupported OCSP CertID hash")),
        };
        if serial != leaf_serial
            || id.issuer_name_hash.as_bytes()
                != digest::digest(algorithm, issuer.subject().as_raw()).as_ref()
            || id.issuer_key_hash.as_bytes()
                != digest::digest(algorithm, &issuer.public_key().subject_public_key.data).as_ref()
        {
            continue;
        }
        let this_update = single.this_update.0.to_unix_duration().as_secs();
        // ponytail: no nextUpdate means a 24h lifetime; configure only if a responder requires it.
        let next_update = single
            .next_update
            .map(|time| time.0.to_unix_duration().as_secs())
            .unwrap_or(this_update + 24 * 60 * 60);
        if matched.is_some()
            || this_update > now + 300
            || next_update < now
            || next_update < this_update
            || produced < this_update
        {
            return Err(invalid("OCSP freshness or uniqueness check failed"));
        }
        matched = Some(match &single.cert_status {
            CertStatus::Good(_) => false,
            CertStatus::Revoked(info) => {
                if info.revocation_time.0.to_unix_duration().as_secs() > now + 300 {
                    return Err(invalid("future OCSP revocation time"));
                }
                true
            }
            CertStatus::Unknown(_) => return Err(invalid("OCSP certificate status is unknown")),
        });
    }
    match matched {
        Some(false) => Ok(()),
        Some(true) => Err(Error::CertificateRevoked),
        None => Err(invalid("OCSP response does not cover this certificate")),
    }
}
