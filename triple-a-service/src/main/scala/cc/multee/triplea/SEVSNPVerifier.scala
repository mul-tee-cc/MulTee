package cc.multee.triplea

import cats.data.{Ior, NonEmptyChain => Nec}
import cats.syntax.all._
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import API._
import Err._
import cc.multee.triplea.Attestation.teeMismatch
import cc.multee.triplea.DCAPVerifier.CsrAttestation
import cc.multee.triplea.ReportParserAMDSEVSNP.{ReportSEVSNP, Signature => SnpSig}

object SEVSNPVerifier extends Verifier {

//  private val curveName = "secp384r1"
  val sigAlgo = "SHA384withECDSA"

  case class ChipId(value: Array[Byte]) extends Policy.HWRef {
    override def getId: Array[Byte] = value
  }


  def validate(attQuote: CsrAttestation): Either[Issues,Policy.CsrAttestationVerification[ChipId]] = {

    for {
      teeReport <- attQuote.raw.teeReport.value match {
        case sevsnp: TeeReportValue.SEVSNP => Right(sevsnp)
        case _ => Left(teeMismatch)
      }

      report <- ReportParserAMDSEVSNP.parse(attQuote.body).leftMap(Nec.one)

      vekDer <- Util.validateB64(teeReport.vekCert,TripleaIssue.PUB_KEY_PARSING).toEither
      vekCert <- certFromDer(vekDer,"VEK").leftMap(Nec.one)
      vekPubKey = vekCert.getPublicKey

      valid <- (
        nonProdValidation(validateSig(vekPubKey, attQuote.body.take(672), report.signature.toDER, TripleaIssue.SEVSNP_REPORT_SIG, "Incorrect Report signature")),
        validateDebugMode(report),
        validateCert(certFromDer(vekDer,"leaf"), teeReport.intermediateCA),
        validateCert(certFromPEM(teeReport.intermediateCA,"Intermediate CA"),SNP_MILAN_ROOT_CA),
      ).mapN(validateAll).toEither
    } yield valid(attQuote,report)
  }

  private def validateAll( _signature: MTValid[ValidatedSignature], _launchMeasuement: MTValid[DebugMode], _vek: MTValid[Cert], _intermediate: MTValid[Cert])
                         (attQuote: CsrAttestation, report: ReportSEVSNP): Policy.CsrAttestationVerification[ChipId] = {
    Policy.CsrAttestationVerification(attQuote.csr, ChipId(report.body.chip_id.toArray))
  }

  private class DebugMode
  private def validateDebugMode(report: ReportSEVSNP): Issues Ior MTValid[DebugMode] =
    if(!report.body.policy.debug) Ior.right(MTValid())
    else nonProdValidation(issueT(TripleaIssue.SEVSNP_IN_DEBUG_MODE, "CoVM is running in DEBUG mode"))

  private val SNP_MILAN_ROOT_CA: String =
  """-----BEGIN CERTIFICATE-----
    |MIIGYzCCBBKgAwIBAgIDAQAAMEYGCSqGSIb3DQEBCjA5oA8wDQYJYIZIAWUDBAIC
    |BQChHDAaBgkqhkiG9w0BAQgwDQYJYIZIAWUDBAICBQCiAwIBMKMDAgEBMHsxFDAS
    |BgNVBAsMC0VuZ2luZWVyaW5nMQswCQYDVQQGEwJVUzEUMBIGA1UEBwwLU2FudGEg
    |Q2xhcmExCzAJBgNVBAgMAkNBMR8wHQYDVQQKDBZBZHZhbmNlZCBNaWNybyBEZXZp
    |Y2VzMRIwEAYDVQQDDAlBUkstTWlsYW4wHhcNMjAxMDIyMTcyMzA1WhcNNDUxMDIy
    |MTcyMzA1WjB7MRQwEgYDVQQLDAtFbmdpbmVlcmluZzELMAkGA1UEBhMCVVMxFDAS
    |BgNVBAcMC1NhbnRhIENsYXJhMQswCQYDVQQIDAJDQTEfMB0GA1UECgwWQWR2YW5j
    |ZWQgTWljcm8gRGV2aWNlczESMBAGA1UEAwwJQVJLLU1pbGFuMIICIjANBgkqhkiG
    |9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsVmD7FktuotWwX1fNg
    |W41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU0V5tkKiU1EesNFta
    |1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S1ju8X93+6dxDUrG2
    |SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI52Naz5m2B+O+vjsC0
    |60d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3KFYXP59XmJgtcog05
    |gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd/y8KxX7jksTEzAOg
    |bKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBkgnlENEWx1UcbQQrs
    |+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V9TJQqnN3Q53kt5vi
    |Qi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnqz55I0u33wh4r0ZNQ
    |eTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+OgpCCoMNit2uLo9M18
    |fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXoQPHfbkH0CyPfhl1j
    |WhJFZasCAwEAAaN+MHwwDgYDVR0PAQH/BAQDAgEGMB0GA1UdDgQWBBSFrBrRQ/fI
    |rFXUxR1BSKvVeErUUzAPBgNVHRMBAf8EBTADAQH/MDoGA1UdHwQzMDEwL6AtoCuG
    |KWh0dHBzOi8va2RzaW50Zi5hbWQuY29tL3ZjZWsvdjEvTWlsYW4vY3JsMEYGCSqG
    |SIb3DQEBCjA5oA8wDQYJYIZIAWUDBAICBQChHDAaBgkqhkiG9w0BAQgwDQYJYIZI
    |AWUDBAICBQCiAwIBMKMDAgEBA4ICAQC6m0kDp6zv4Ojfgy+zleehsx6ol0ocgVel
    |ETobpx+EuCsqVFRPK1jZ1sp/lyd9+0fQ0r66n7kagRk4Ca39g66WGTJMeJdqYriw
    |STjjDCKVPSesWXYPVAyDhmP5n2v+BYipZWhpvqpaiO+EGK5IBP+578QeW/sSokrK
    |dHaLAxG2LhZxj9aF73fqC7OAJZ5aPonw4RE299FVarh1Tx2eT3wSgkDgutCTB1Yq
    |zT5DuwvAe+co2CIVIzMDamYuSFjPN0BCgojl7V+bTou7dMsqIu/TW/rPCX9/EUcp
    |KGKqPQ3P+N9r1hjEFY1plBg93t53OOo49GNI+V1zvXPLI6xIFVsh+mto2RtgEX/e
    |pmMKTNN6psW88qg7c1hTWtN6MbRuQ0vm+O+/2tKBF2h8THb94OvvHHoFDpbCELlq
    |HnIYhxy0YKXGyaW1NjfULxrrmxVW4wcn5E8GddmvNa6yYm8scJagEi13mhGu4Jqh
    |3QU3sf8iUSUr09xQDwHtOQUVIqx4maBZPBtSMf+qUDtjXSSq8lfWcd8bLr9mdsUn
    |JZJ0+tuPMKmBnSH860llKk+VpVQsgqbzDIvOLvD6W1Umq25boxCYJ+TuBoa4s+HH
    |CViAvgT9kf/rBq1d+ivj6skkHxuzcxbk1xv6ZGxrteJxVH7KlX7YRdZ6eARKwLe4
    |AFZEAwoKCQ==
    |-----END CERTIFICATE-----
    |""".stripMargin
}
