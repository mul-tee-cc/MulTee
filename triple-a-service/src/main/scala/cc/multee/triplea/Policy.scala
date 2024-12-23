package cc.multee.triplea

import cats.data.Ior
import cats.syntax.all._
import Err._
import cc.multee.triplea.DCAPVerifier.EcdsaId
import cc.multee.triplea.SEVSNPVerifier.ChipId
import org.bouncycastle.asn1.x500.style.RFC4519Style
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder
import org.bouncycastle.pkcs.PKCS10CertificationRequest

import java.security.cert.{Certificate, X509Certificate}

class ApplicationIdentity
class Location
class KeyRbac

case class Hostname(value: String) extends AnyVal
case class AppId(value: String) extends AnyVal
case class Role(value: String) extends AnyVal

object Policy {

  trait HWRef {
    def getId: Array[Byte]
  }

  case class CsrAttestationVerification[T <: Policy.HWRef](payload: PKCS10CertificationRequest, hwRef: T)

  private type LocationPolicyCheck[T] = (T,Hostname) => Boolean

  private def dummyPolicy[T] = ("multee-client","acct", (_:T,_:Hostname) => false)

  private def allowedAppId(identity: Array[Certificate], appId: AppId): Issues Ior MTValid[ApplicationIdentity] = {
    if(getCN(identity(0).asInstanceOf[X509Certificate]) == appId.value) Ior.right(MTValid())
    else issueT(TripleaIssue.POLICY_VIOLATION, "Prohibited application identity")
  }

  private def allowedLocation[T](hostname: Hostname, hwRef: T, predicate: LocationPolicyCheck[T]): Issues Ior MTValid[Location] = {
    if(predicate(hwRef,hostname)) Ior.right(MTValid())
    else nonProdValidation(issueT(TripleaIssue.UNIMPLEMENTED_TODO,
      s"""Need to check some or all of
         |hostname: ${hostname.value}
         |hwRef: $hwRef
         |""".stripMargin))
  }

  private def allowedRole(csr: PKCS10CertificationRequest, role: Role): Issues Ior MTValid[KeyRbac] = {
    if(csr.getSubject.getRDNs(RFC4519Style.cn)(0).getFirst.getValue.toString == role.value) Ior.right(MTValid())
    else issueT(TripleaIssue.POLICY_VIOLATION, "Prohibited role")
  }

  private def getCN(cert: X509Certificate): String =
    new JcaX509CertificateHolder(cert).getSubject.getRDNs(RFC4519Style.cn)(0).getFirst.getValue.toString

  def validate[T <: HWRef](attestationPl: Policy.CsrAttestationVerification[T], hostname: Hostname, identity: Array[Certificate]):  Issues Ior PKCS10CertificationRequest = {

    (allowedAppId(identity,AppId(dummyPolicy._1)),
      allowedRole(attestationPl.payload,Role(dummyPolicy._2)),
      allowedLocation(hostname,attestationPl.hwRef,dummyPolicy._3)
    ).mapN((_unit1,_unit2,_unit3) =>attestationPl.payload )

  }

  // SEV-SNP
  class AllowedCXL // CXL may simplify memory replay attacks (vs memory module interposer)
  class CrossSocketGuest // May allow some classes of micro-architectural side channel attacks
  class RunningAveragePowerLimit // power measurement
  class GuestMigrationAgent // Live migration of CoVM


}
