package cc.multee.triplea

import cats.data.{Ior, NonEmptyChain => Nec}
import cats.syntax.all._
import cc.multee.triplea.QuoteParserIntelDCAP.SgxQuote3
import org.bouncycastle.pkcs.PKCS10CertificationRequest

import scala.util.Try
import API._
import Err._
import cc.multee.triplea.Attestation.teeMismatch

object DCAPVerifier extends Verifier {

  private val curveName = "secp256r1" // == prime256v1
  val sigAlgo = "SHA256withECDSA"
  private val PCK_CERT_CHAIN_KEY_TYPE = 5
  private val SGX_FLAGS_DEBUG= 0x0000000000000002;

//  case class CsrAttestationVerification[Ec(payload: PKCS10CertificationRequest, qe_id: EcdsaId)

  case class CsrAttestation(csr: PKCS10CertificationRequest, body: Array[Byte], raw: AttestationStruct)(_nonce: MTValid[Nonce])

  def validate(attQuote: CsrAttestation): Either[Issues,Policy.CsrAttestationVerification[EcdsaId]] = {

    for {
      teeReport <- attQuote.raw.teeReport.value match {
        case dcap: TeeReportValue.DCAP => Right(dcap)
        case _ => Left(teeMismatch)
      }

      quote <- QuoteParserIntelDCAP.parse(attQuote.body).leftMap(Nec.one)

      pckPubKey <- pubKeyFromPEM(teeReport.pck,"PCK").leftMap(Nec.one)
      attPubKey <- pubKeyFromBytes(curveName,quote.sig_data.attest_pub_key.toArray,TripleaIssue.PUB_KEY_PARSING, "Unable to parse QE public key:" ).leftMap(Nec.one)

      valid <- (
        validateCertKeyType(quote),
        validateSig(pckPubKey,quote.sig_data.qe_report.toBytes,quote.sig_data.qe_report_sig.toDER,TripleaIssue.QE_SIGNATURE,"Incorrect PCK signature over Quoting enclave"),
        validateSig(attPubKey,quote.header.toBytes.concat(quote.report_body.toBytes),quote.sig_data.sig.toDER,TripleaIssue.ENCLAVE_SIGNATURE, "Incorrect QE signature over MulTee enclave"),
        validatePayload(attQuote.raw.payload.value.getBytes,quote),
        validateCert(certFromPEM(teeReport.pck,"leaf"), teeReport.intermediateCA),
        validateCert(certFromPEM(teeReport.intermediateCA,"Intermediate CA"), INTEL_ROOT_CA),
        validateRevokedPCK(teeReport.pck),
        validatePlatform(quote),
        validateQeVersion(quote),
        validateMulTeeVersion(quote),
        validateDebugMode(quote)
      ).mapN(validateAll).toEither
    } yield valid(attQuote,quote)
  }

  private def validateAll(_cert: MTValid[KeyType], _quotingEnclave: MTValid[ValidatedSignature], _enclave: MTValid[ValidatedSignature], _hash: MTValid[Payload],
                          _pck: MTValid[Cert], _intermediate: MTValid[Cert], _revoke: MTValid[PCKRevocation], _p: MTValid[Platform],
                          _qe: MTValid[EnclaveVersion], _mulTee: MTValid[EnclaveVersion], _debug: MTValid[DebugMode])
                 (attQuote: CsrAttestation, quote: SgxQuote3): Policy.CsrAttestationVerification[EcdsaId] = {
    Policy.CsrAttestationVerification(attQuote.csr, EcdsaId(quote.header.user_data.qe_id.toArray))
  }

  class Payload
  private def validatePayload(payload: Array[Byte], quote: SgxQuote3): Issues Ior MTValid[Payload] = {

    scribe.trace("Checking whether payload hash matches quote")

    val payloadHash = Util.sha256(payload)
    val quoteHash = quote.report_body.report_data.toArray.take(32)

    if(payloadHash sameElements quoteHash) Ior.right(MTValid())
    else nonProdValidation(issueT(TripleaIssue.CORRUPT_QUOTE_REQUEST_PAYLOAD, "Corrupted quote request payload: hash mismatch"))
  }

  private class PCKRevocation
  private def validateRevokedPCK(_cert: String): Issues Ior MTValid[PCKRevocation] = nonProdValidation(
    issueT(TripleaIssue.UNIMPLEMENTED_TODO,"Need to check whether PCK cert is revoked")
  )

  private class KeyType
  private def validateCertKeyType(quote: SgxQuote3): Issues Ior MTValid[KeyType] = {
    scribe.info(s"Checking whether cert chain type is supported ( PCK_CERT_CHAIN_KEY_TYPE: ${quote.sgx_ql_certification_data.cert_key_type})")
    if(quote.sgx_ql_certification_data.cert_key_type == PCK_CERT_CHAIN_KEY_TYPE) Ior.right(MTValid())
    else issueT(TripleaIssue.UNSUPPORTED_CERT_CHAIN_KEY_TYPE, s"Unsupported cert chain key type")
  }


  private class EnclaveVersion
  private def validateQeVersion(quote: SgxQuote3): Issues Ior MTValid[EnclaveVersion] =
    nonProdValidation(issueT(TripleaIssue.UNIMPLEMENTED_TODO,
      s"""Quoting enclave must be of compliant version. Need to check some or all of
         |quote.sig_data.qe_report.isv_svn: ${quote.sig_data.qe_report.isv_svn}
         |quote.sig_data.qe_report.isv_prod_id: ${quote.sig_data.qe_report.isv_prod_id}
         |quote.sig_data.qe_report.mr_signer: ${quote.sig_data.qe_report.mr_signer}
         |quote.sig_data.qe_report.mr_enclave: ${quote.sig_data.qe_report.mr_enclave}
         |""".stripMargin))

  private def validateMulTeeVersion(quote: SgxQuote3): Issues Ior MTValid[EnclaveVersion] =
    nonProdValidation(issueT(TripleaIssue.UNIMPLEMENTED_TODO,
      s"""MulTee enclave must be of compliant version. Need to check some or all of
         |quote.report_body.isv_svn: ${quote.report_body.isv_svn}
         |quote.report_body.isv_prod_id: ${quote.report_body.isv_prod_id}
         |quote.report_body.mr_signer: ${quote.report_body.mr_signer}
         |quote.report_body.mr_enclave: ${quote.report_body.mr_enclave}
         |""".stripMargin))

  private class DebugMode
  private def validateDebugMode(quote: SgxQuote3): Issues Ior MTValid[DebugMode] =
    if((quote.report_body.attributes.flags & SGX_FLAGS_DEBUG) == 0) Ior.right(MTValid())
    else nonProdValidation(issueT(TripleaIssue.ENCALVE_IN_DEBUG_MODE, "Enclave is running in DEBUG mode"))


  private class Platform
  private def validatePlatform(quote: SgxQuote3): Issues Ior MTValid[Platform] =
    nonProdValidation(issueT(TripleaIssue.UNIMPLEMENTED_TODO,
      s"""Platform running MulTee may need to come from trusted pool. Check ECDSA_ID against
         |ECDSA_ID: ${getEcdsaId(quote).value}
         |""".stripMargin))




  case class EcdsaId(value: Array[Byte]) extends Policy.HWRef {
    override def getId: Array[Byte] = value
  }

  private def getEcdsaId(quote: SgxQuote3): EcdsaId = {

    val attPubKeyBytes = quote.sig_data.attest_pub_key.toArray
    val autData = quote.auth_certification_data.auth_data.toArray
    EcdsaId(Util.sha256(attPubKeyBytes.concat(autData)))
  }

  val pck: String =
    """-----BEGIN CERTIFICATE-----
      |MIIE8zCCBJmgAwIBAgIVAP0xmGUITP0KtO5qkSuVeZuWsbfaMAoGCCqGSM49BAMC
      |MHAxIjAgBgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoM
      |EUludGVsIENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UE
      |CAwCQ0ExCzAJBgNVBAYTAlVTMB4XDTIzMDcyOTAwMzA0MloXDTMwMDcyOTAwMzA0
      |MlowcDEiMCAGA1UEAwwZSW50ZWwgU0dYIFBDSyBDZXJ0aWZpY2F0ZTEaMBgGA1UE
      |CgwRSW50ZWwgQ29ycG9yYXRpb24xFDASBgNVBAcMC1NhbnRhIENsYXJhMQswCQYD
      |VQQIDAJDQTELMAkGA1UEBhMCVVMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAASF
      |uLZ04Pm7uomqGjvG22dUsiBy9SqPB7tlcRuF//RJ4yoM9UBeWwefMNU/pWfMMMee
      |wN1qZL6A8cMnTRMrn64Yo4IDDjCCAwowHwYDVR0jBBgwFoAUlW9dzb0b4elAScnU
      |9DPOAVcL3lQwawYDVR0fBGQwYjBgoF6gXIZaaHR0cHM6Ly9hcGkudHJ1c3RlZHNl
      |cnZpY2VzLmludGVsLmNvbS9zZ3gvY2VydGlmaWNhdGlvbi92My9wY2tjcmw/Y2E9
      |cGxhdGZvcm0mZW5jb2Rpbmc9ZGVyMB0GA1UdDgQWBBQWSim/IpMuZy+6rOas7vtt
      |qZt4zjAOBgNVHQ8BAf8EBAMCBsAwDAYDVR0TAQH/BAIwADCCAjsGCSqGSIb4TQEN
      |AQSCAiwwggIoMB4GCiqGSIb4TQENAQEEEFwGbSYdpx6tw3+BZmP0R3MwggFlBgoq
      |hkiG+E0BDQECMIIBVTAQBgsqhkiG+E0BDQECAQIBCzAQBgsqhkiG+E0BDQECAgIB
      |CzAQBgsqhkiG+E0BDQECAwIBAzAQBgsqhkiG+E0BDQECBAIBAzARBgsqhkiG+E0B
      |DQECBQICAP8wEQYLKoZIhvhNAQ0BAgYCAgD/MBAGCyqGSIb4TQENAQIHAgEBMBAG
      |CyqGSIb4TQENAQIIAgEAMBAGCyqGSIb4TQENAQIJAgEAMBAGCyqGSIb4TQENAQIK
      |AgEAMBAGCyqGSIb4TQENAQILAgEAMBAGCyqGSIb4TQENAQIMAgEAMBAGCyqGSIb4
      |TQENAQINAgEAMBAGCyqGSIb4TQENAQIOAgEAMBAGCyqGSIb4TQENAQIPAgEAMBAG
      |CyqGSIb4TQENAQIQAgEAMBAGCyqGSIb4TQENAQIRAgENMB8GCyqGSIb4TQENAQIS
      |BBALCwMD//8BAAAAAAAAAAAAMBAGCiqGSIb4TQENAQMEAgAAMBQGCiqGSIb4TQEN
      |AQQEBgBgagAAADAPBgoqhkiG+E0BDQEFCgEBMB4GCiqGSIb4TQENAQYEEMx3pK6i
      |PaQvgN0Wg1yid5swRAYKKoZIhvhNAQ0BBzA2MBAGCyqGSIb4TQENAQcBAQH/MBAG
      |CyqGSIb4TQENAQcCAQEAMBAGCyqGSIb4TQENAQcDAQEAMAoGCCqGSM49BAMCA0gA
      |MEUCIHO9+LYv7D211mv4WcFB5s81H0yjsUq1kUE73mM6fnHdAiEA3k3UuLalqt2C
      |F6oQG94ZrDvZLZ2CjIx3WieG7u5xJtE=
      |-----END CERTIFICATE-----
      |""".stripMargin

  def test = {
//    val enc = "AwACAAAAAAAJAA4Ak5pyM/ecTKmUCg2zlX8GB2R9Ax8d/sNAkA0pOXKgNYwAAAAADAwQD///AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAADnAAAAAAAAALuhaENkBnkqJl9ii9koNu7/ckLy56M1ALAiuW2tmJqQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB7cEX7bovm0q0H4vS0x3CAMwsLVXc3oIzEOBrr0CCpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyhAAAP0qNE2WlwW3f51bSY3rzwt2tSXxlYNYmaDT3lXBuuwqU5PA/qE1L29ydYNgrrJHPZXZlCze93oiFOE/0JDAOUN8LY8xSqDMJca6RbJYmQZA8r43bdKo61imd5Qnz14cmhPBdyOQQir23gUQoaDa6EuIaHyValakC+g68gaA6YMlDAwQD///AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAADnAAAAAAAAABkqpQzhwM7wPM+J57Wxaw15ePXCse3Pd02HcC6BVNi/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4LJD9K5Xo4ZjLeVuS4QtXBGcW7zdAn8H3RkleavyUDQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANXFizwgC02ZIre8oKe5ZdCabdnwmU3gIsGhrGujD7RyUWlrG7oC+UeZNMZ5wbZ18UwHDw0+VsJlDusBxIKkDCSAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FAGIOAAA="
    val enc = "AwACAAAAAAAJAA4Ak5pyM/ecTKmUCg2zlX8GB2R9Ax8d/sNAkA0pOXKgNYwAAAAADAwQD///AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABwAAAAAAAADnAAAAAAAAAH4MaCcp82l5vdtRMgeENt/PLfbRaTCp9DI7O0diIg+7AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACD1xnnferKFHD2uvYqTXdDA8iZ22kCD5xw7h38CMfOngAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABB7cEX7bovm0q0H4vS0x3CAMwsLVXc3oIzEOBrr0CCpAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAyhAAABM2bva8BXc154Uh9A2pZ/hsd1irvDSsWIEdQyp36rZwpXf2Y9CC3BP50d0+EGQCEm1LGcgIYTK1Xvvymg+46HN8LY8xSqDMJca6RbJYmQZA8r43bdKo61imd5Qnz14cmhPBdyOQQir23gUQoaDa6EuIaHyValakC+g68gaA6YMlDAwQD///AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFQAAAAAAAADnAAAAAAAAABkqpQzhwM7wPM+J57Wxaw15ePXCse3Pd02HcC6BVNi/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAACMT1d115ZQPpYTf3fGioKaAFasje1wFAsIGwlEkMV7/wAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEACQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD4LJD9K5Xo4ZjLeVuS4QtXBGcW7zdAn8H3RkleavyUDQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALWj3lqxjwUCS8qX710rHV0/sgpVxcOVl8wKHptPRE9fcaGPGIS04iIs43+f1FUqSrVqfCbM+JWGbnXw/GmTNNyAAAAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8FAGIOAAA="

    val intermediate: String =
      """-----BEGIN CERTIFICATE-----
        |MIICljCCAj2gAwIBAgIVAJVvXc29G+HpQEnJ1PQzzgFXC95UMAoGCCqGSM49BAMC
        |MGgxGjAYBgNVBAMMEUludGVsIFNHWCBSb290IENBMRowGAYDVQQKDBFJbnRlbCBD
        |b3Jwb3JhdGlvbjEUMBIGA1UEBwwLU2FudGEgQ2xhcmExCzAJBgNVBAgMAkNBMQsw
        |CQYDVQQGEwJVUzAeFw0xODA1MjExMDUwMTBaFw0zMzA1MjExMDUwMTBaMHAxIjAg
        |BgNVBAMMGUludGVsIFNHWCBQQ0sgUGxhdGZvcm0gQ0ExGjAYBgNVBAoMEUludGVs
        |IENvcnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0Ex
        |CzAJBgNVBAYTAlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAENSB/7t21lXSO
        |2Cuzpxw74eJB72EyDGgW5rXCtx2tVTLq6hKk6z+UiRZCnqR7psOvgqFeSxlmTlJl
        |eTmi2WYz3qOBuzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBS
        |BgNVHR8ESzBJMEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2Vy
        |dmljZXMuaW50ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUlW9d
        |zb0b4elAScnU9DPOAVcL3lQwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYB
        |Af8CAQAwCgYIKoZIzj0EAwIDRwAwRAIgXsVki0w+i6VYGW3UF/22uaXe0YJDj1Ue
        |nA+TjD1ai5cCICYb1SAmD5xkfTVpvo4UoyiSYxrDWLmUR4CI9NKyfPN+
        |-----END CERTIFICATE-----
        |""".stripMargin

    val b = Util.fromB64(enc).toOption.get
    println(QuoteParserIntelDCAP.parse(b))
    val q = QuoteParserIntelDCAP.parse(b).toOption.get

//    println(q.auth_certification_data.size)
//    println(q.auth_certification_data.auth_data)
//    println(q.sgx_ql_certification_data.cert_key_type)
//    println(q.sgx_ql_certification_data.size)

    val payloadStr = "{\"kms_endpoint\":\"\",\"nonce\":\"salt\",\"requested_keys\":[\"RsaKey\"],\"wrapping_public_key\":\"---PK---\"}"

//    val aqr = AttestationRequest(payloadStr,enc,pck,intermediate,Map())
//    val payload = CsrPayload("","")
//    val aq = AttestationQuote(payload,b,aqr)
//    println(validate(aq))


  }

  private val INTEL_ROOT_CA: String =
    """-----BEGIN CERTIFICATE-----
      |MIICjzCCAjSgAwIBAgIUImUM1lqdNInzg7SVUr9QGzknBqwwCgYIKoZIzj0EAwIw
      |aDEaMBgGA1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENv
      |cnBvcmF0aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJ
      |BgNVBAYTAlVTMB4XDTE4MDUyMTEwNDUxMFoXDTQ5MTIzMTIzNTk1OVowaDEaMBgG
      |A1UEAwwRSW50ZWwgU0dYIFJvb3QgQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0
      |aW9uMRQwEgYDVQQHDAtTYW50YSBDbGFyYTELMAkGA1UECAwCQ0ExCzAJBgNVBAYT
      |AlVTMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEC6nEwMDIYZOj/iPWsCzaEKi7
      |1OiOSLRFhWGjbnBVJfVnkY4u3IjkDYYL0MxO4mqsyYjlBalTVYxFP2sJBK5zlKOB
      |uzCBuDAfBgNVHSMEGDAWgBQiZQzWWp00ifODtJVSv1AbOScGrDBSBgNVHR8ESzBJ
      |MEegRaBDhkFodHRwczovL2NlcnRpZmljYXRlcy50cnVzdGVkc2VydmljZXMuaW50
      |ZWwuY29tL0ludGVsU0dYUm9vdENBLmRlcjAdBgNVHQ4EFgQUImUM1lqdNInzg7SV
      |Ur9QGzknBqwwDgYDVR0PAQH/BAQDAgEGMBIGA1UdEwEB/wQIMAYBAf8CAQEwCgYI
      |KoZIzj0EAwIDSQAwRgIhAOW/5QkR+S9CiSDcNoowLuPRLsWGf/Yi7GSX94BgwTwg
      |AiEA4J0lrHoMs+Xo5o/sX6O9QWxHRAvZUGOdRQ7cvqRXaqI=
      |-----END CERTIFICATE-----
      |""".stripMargin

}
