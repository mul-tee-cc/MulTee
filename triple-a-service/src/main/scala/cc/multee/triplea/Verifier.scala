package cc.multee.triplea

import cats.data.{Ior, NonEmptyChain => Nec}
import cats.syntax.all._
import Err.{Issue, Issues, MTValid, TripleaIssue, issue, issueT}
import org.bouncycastle.jce.ECPointUtil
import org.bouncycastle.pkcs.PKCS10CertificationRequest

import java.io.ByteArrayInputStream
import java.security.cert.{CertificateFactory, X509Certificate}
import java.security.spec.{ECGenParameterSpec, ECParameterSpec, ECPublicKeySpec}
import java.security.{AlgorithmParameters, KeyFactory, PublicKey, Signature}
import scala.util.{Failure, Success, Try}

trait Verifier {

  private val UNCOMPRESSED_EC_PUB_KEY: Byte = 4

  def sigAlgo: String

  class ValidatedSignature

  class Cert
  def validateCert(cert: => Either[Issue, X509Certificate], ca: String): Issues Ior MTValid[Cert] = {

    val x: Either[Issue,Unit] =
      for {
        caCert <- certFromPEM(ca,"CA")
        crt <- cert
        r <- Try(crt.verify(caCert.getPublicKey)).toEither
          .leftMap(e => Issue(TripleaIssue.PCK_CERT_CHAIN, s"Unable to verify cert ${e.getMessage}"))
      } yield r
    x.bimap(Nec.one,_ => MTValid[Cert]()).toIor
  }

  def validateSig(pk: PublicKey, msg: Array[Byte], sig: Array[Byte], errCode: TripleaIssue.Type, errMsg: String): Issues Ior MTValid[ValidatedSignature] = Try {
    val signer = Signature.getInstance(sigAlgo)
    signer.initVerify(pk)
    signer.update(msg)
    signer.verify(sig)
  } match {
    case Failure(e) => issueT(TripleaIssue.INVALID_PUB_KEY, s"Invalid public key or signature: ${e.getMessage} (library issue?)")
    case Success(true) => Ior.right(MTValid())
    case Success(false) => issueT(errCode, errMsg)
  }

  def pubKeyFromBytes(curveName: String, bytes: Array[Byte], errCode: TripleaIssue.Type, errMsg: String): Either[Issue,PublicKey] = Try {

    val encoded = Array(UNCOMPRESSED_EC_PUB_KEY).concat(bytes)

    val parameters = AlgorithmParameters.getInstance("EC")
    parameters.init(new ECGenParameterSpec(curveName))
    val ecParameters = parameters.getParameterSpec(classOf[ECParameterSpec])
    val ellipticCurve = ecParameters.getCurve
    val point = ECPointUtil.decodePoint(ellipticCurve, encoded)
    val keySpec = new ECPublicKeySpec(point, ecParameters)

    KeyFactory.getInstance("EC").generatePublic(keySpec)
  } match {
    case Success(pub) => Right(pub)
    case Failure(e) => issue(errCode, s"$errMsg ${e.getMessage}")
  }

  def pubKeyFromPEM(cert: String, name: String): Either[Issue,PublicKey] =
    certFromPEM(cert, name).map(_.getPublicKey)

  def certFromPEM(cert: String, name: String): Either[Issue,X509Certificate] = certFromDer(cert.getBytes(), name)

  def certFromDer(cert: Array[Byte], name: String): Either[Issue,X509Certificate] = Try {
    CertificateFactory.getInstance("x509")
      .generateCertificate(new ByteArrayInputStream(cert))
      .asInstanceOf[X509Certificate]
  } match {
    case Success(cert) => Right(cert)
    case Failure(e) => issue(TripleaIssue.CERT_PARSING,s"Unable to parse $name certificate: ${e.getMessage}")
  }



}
