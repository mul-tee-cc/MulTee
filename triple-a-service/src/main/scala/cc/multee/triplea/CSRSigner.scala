package cc.multee.triplea

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo
import org.bouncycastle.asn1.x500.{X500Name, X500NameBuilder}
import org.bouncycastle.asn1.x509._
import org.bouncycastle.asn1.{ASN1Encodable, ASN1ObjectIdentifier, DERSequence}
import org.bouncycastle.cert.{X509CertificateHolder, X509v3CertificateBuilder}
import org.bouncycastle.crypto.util.PrivateKeyFactory
import org.bouncycastle.jce.X509KeyUsage
import org.bouncycastle.openssl.jcajce.{JcaPEMKeyConverter, JceOpenSSLPKCS8DecryptorProviderBuilder, JcePEMDecryptorProviderBuilder}
import org.bouncycastle.openssl.{PEMEncryptedKeyPair, PEMKeyPair}
import org.bouncycastle.operator.bc.BcRSAContentSignerBuilder
import org.bouncycastle.operator.{ContentSigner, DefaultDigestAlgorithmIdentifierFinder, DefaultSignatureAlgorithmIdentifierFinder}
import org.bouncycastle.pkcs.{PKCS10CertificationRequest, PKCS8EncryptedPrivateKeyInfo}
import org.bouncycastle.asn1.x500.style.RFC4519Style

import java.math.BigInteger
import java.util.Date

class CSRSigner(certPEM: String, keyPEM: String, passwd: String ) {
  import CSRSigner._

  private val cert = Util.parsePEM(certPEM).asInstanceOf[X509CertificateHolder]

  private val publicKeyInfo = cert.getSubjectPublicKeyInfo
  private val privateKey = getPrivateKey( keyPEM, passwd.toCharArray )
  private val subject = cert.getSubject

  private def getDN: String = subject.toString

  private def signer( algorithm: String ): ContentSigner = {

    val sigAlgId = new DefaultSignatureAlgorithmIdentifierFinder().find(algorithm)
    val digAlgId = new DefaultDigestAlgorithmIdentifierFinder().find(sigAlgId)
    new BcRSAContentSignerBuilder(sigAlgId, digAlgId).build(PrivateKeyFactory.createKey(privateKey.getEncoded))
  }

  def sign(csr: PKCS10CertificationRequest, addRDNs: (ASN1ObjectIdentifier, String)* ): X509CertificateHolder = {

    val rdns =  addRDNs :+ (RFC4519Style.cn, csr.getSubject.getRDNs(RFC4519Style.cn)(0).getFirst.getValue.toString)

    val x500nameBuilder = new X500NameBuilder

    val x500name = rdns
      .foldLeft(x500nameBuilder)( (x500,rdn) => x500.addRDN(rdn._1,rdn._2) )
      .build

    val serialNo = new BigInteger(System.currentTimeMillis().toString)

    val time = System.currentTimeMillis()
    val validFrom = new Date(time - 1000000000)
    val validTo   = new Date(time + 2000000000)

    val newCertBuilder = new X509v3CertificateBuilder( new X500Name(getDN), serialNo, validFrom, validTo, x500name, csr.getSubjectPublicKeyInfo)

    val certBuilder = addExtensions(newCertBuilder, publicKeyInfo )

    val certHolder = certBuilder.build(signer(signatureAlgorithm))

    certHolder
  }

}
object CSRSigner {

  private val signatureAlgorithm = "SHA256withRSA"

  private def addExtensions(in: X509v3CertificateBuilder, parentPubKeyInfo: SubjectPublicKeyInfo, SANs: String*) = {

    if( SANs.nonEmpty ) {
      val subjectAlternativeNames = new DERSequence(SANs.map(new GeneralName(GeneralName.dNSName, _)).toArray(scala.reflect.classTag[ASN1Encodable]))

      in.addExtension(Extension.subjectAlternativeName, false, subjectAlternativeNames)
    }

    val keyUsage = new X509KeyUsage(0
      | X509KeyUsage.digitalSignature
      | X509KeyUsage.nonRepudiation
      | X509KeyUsage.keyEncipherment
      | X509KeyUsage.dataEncipherment
    )

    val extUsage = new ExtendedKeyUsage(Array[KeyPurposeId](KeyPurposeId.id_kp_clientAuth) )

    in.addExtension(Extension.basicConstraints, false, new BasicConstraints(false)) // true if it is allowed to sign other certs
      .addExtension(Extension.keyUsage, true, keyUsage)
      .addExtension(Extension.authorityKeyIdentifier, false, new AuthorityKeyIdentifier(parentPubKeyInfo))
      .addExtension(Extension.extendedKeyUsage, false, extUsage) // PyKMIP depends on this, doesn't care about rest
  }

  private def getPrivateKey(pem: String, password: Array[Char]): java.security.PrivateKey = {

    val pemKP = Util.parsePEM(pem)
    val converter = new JcaPEMKeyConverter().setProvider("BC")
    pemKP match {
      case unencryptedPEM: PEMKeyPair => converter.getKeyPair(unencryptedPEM).getPrivate
      case encrypted: PEMEncryptedKeyPair =>
        converter.getKeyPair(encrypted.decryptKeyPair(new JcePEMDecryptorProviderBuilder().build(password))).getPrivate
      case unencrypted: PrivateKeyInfo => converter.getPrivateKey(unencrypted)
      case encrypted: PKCS8EncryptedPrivateKeyInfo =>
        converter.getPrivateKey(encrypted.decryptPrivateKeyInfo(new JceOpenSSLPKCS8DecryptorProviderBuilder().build(password)))
    }
  }
}
