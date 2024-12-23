package cc.multee.triplea

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.{ConnectionContext, HttpsConnectionContext}
import cats.data.Ior
import cc.multee.triplea.APIServer.RESTError
import Err.Issues
import Err.TripleaIssue
import Err.issueT
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.openssl.{MiscPEMGenerator, PEMParser}
import org.bouncycastle.pkcs.PKCS10CertificationRequest
import org.bouncycastle.util.io.pem.PemWriter

import java.io._
import java.nio.charset.Charset
import java.security.cert.CertificateFactory
import java.security.{KeyStore, MessageDigest, SecureRandom, Security}
import java.util.Base64
import javax.net.ssl.{KeyManagerFactory, SSLContext, TrustManagerFactory}
import scala.util.{Failure, Success, Try, Using}

object Util {

  private val utf8: Charset = Charset.forName("UTF-8")

  private val mdSHA256 = MessageDigest.getInstance("SHA-256")

  private val b64decoder = Base64.getDecoder
  private val b64encoder = Base64.getEncoder

  def getCert(keyStore: String, pwd: String, trustStore: String): HttpsConnectionContext = {

    Security.addProvider(new BouncyCastleProvider)

    val password: Array[Char] = pwd.toCharArray

    val ks = loadKS(keyStore, password)
    val ts = loadTS(trustStore)

    val keyManagerFactory: KeyManagerFactory = KeyManagerFactory.getInstance("SunX509")
    keyManagerFactory.init(ks, password)

    val tmf: TrustManagerFactory = TrustManagerFactory.getInstance("SunX509")
    tmf.init(ts)

//    val bb: javax.net.ssl.X509TrustManager = tmf.getTrustManagers.apply(0).asInstanceOf[javax.net.ssl.X509TrustManager]
//
//    println(bb.getAcceptedIssuers.length)
//    println(bb.getAcceptedIssuers.apply(0).getIssuerDN)

    val sslContext: SSLContext = SSLContext.getInstance("TLS")
    sslContext.init(keyManagerFactory.getKeyManagers, tmf.getTrustManagers, new SecureRandom)
    val https: HttpsConnectionContext = ConnectionContext.httpsServer { () => {
        val engine = sslContext.createSSLEngine()
        engine.setUseClientMode(false)
        engine.setWantClientAuth(true)
        engine
      }
    }

    https
  }

  private def loadKS(pathname: String, stopword: Array[Char]) = {
    val ks: KeyStore = KeyStore.getInstance("PKCS12")
    val keystore: InputStream = new java.io.FileInputStream(new java.io.File(pathname))

    require(keystore != null, "Keystore required!")
    ks.load(keystore, stopword)
    ks
  }

  private def loadTS(pathname: String) = {
    val ts = KeyStore.getInstance("PKCS12")
    ts.load(null)
    // any client cert signed by this CA is allowed to connect
    ts.setEntry("rootCA",
      new KeyStore.TrustedCertificateEntry(
        CertificateFactory.getInstance("X.509").generateCertificate(new java.io.FileInputStream(new java.io.File(pathname)))),
      null)
    ts
  }

  def sha256(bytes: Array[Byte]): Array[Byte] = mdSHA256.digest(bytes)

  def toB64(b: Array[Byte]): String = new String(b64encoder.encode(b))

  def toB64(s: String): String = toB64(s.getBytes)

  def validateB64(s: String, errKind: TripleaIssue.Type ): Issues Ior Array[Byte] =
    Try {
      b64decoder.decode(s)
    } match {
      case Success(value) => Ior.right(value)
      case Failure(_) => issueT(errKind, "Corrupted base64")
    }

  def fromB64(s: String): Either[RESTError, Array[Byte]] =
    Try {
      b64decoder.decode(s)
    } match {
      case Success(value) => Right(value)
      case Failure(_) => Left(RESTError(StatusCodes.BadRequest, "Corrupted base64"))
    }

  def validateCsr(csr: String, errKind: TripleaIssue.Type): Issues Ior PKCS10CertificationRequest = {
//    println(csr)
    val x = Try(parsePEM(csr))
//    println(x)
    val z =x.flatMap(obj => Try(obj.asInstanceOf[PKCS10CertificationRequest]))
//    println(z)
    z
  }match {
      case Success(value) => Ior.right(value)
      case Failure(_) => issueT(errKind, "Unable to parse CSR")
    }

  def parsePEM(pem: String): AnyRef = {

    val pemStream = new ByteArrayInputStream(pem.getBytes(utf8))
    val pemReader = new BufferedReader(new InputStreamReader(pemStream))
    val pemParser = new PEMParser(pemReader)
    pemParser.readObject
  }

  def readFile(fileName: String): String =
    Using(scala.io.Source.fromFile(fileName))(_.mkString).get

  def makePEM(obj: AnyRef): String = {

    val sw = new StringWriter(4096)
    val pw = new PemWriter(sw)
    pw.writeObject(new MiscPEMGenerator(obj))
    pw.flush()
    sw.toString
  }
}
