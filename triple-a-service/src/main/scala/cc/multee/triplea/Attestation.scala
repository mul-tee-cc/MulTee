package cc.multee.triplea

import akka.http.scaladsl.model.StatusCodes
import akka.http.scaladsl.server._
import cats.data.{Ior, NonEmptyChain => Nec}
import cats.syntax.all._
import cc.multee.triplea.APIServer._
import com.fasterxml.jackson.core.`type`.TypeReference
import com.fasterxml.jackson.module.scala.JsonScalaEnumeration
import spray.json.DefaultJsonProtocol._
import spray.json._

import scala.util.Try

object API {
  class EnumJsonConverter[T <: scala.Enumeration](enu: T) extends RootJsonFormat[T#Value] {
    override def write(obj: T#Value): JsValue = JsString(obj.toString)

    override def read(json: JsValue): T#Value = {
      json match {
        case JsString(txt) => enu.withName(txt)
        case somethingElse => throw DeserializationException(s"Expected a value from enum $enu instead of $somethingElse")
      }
    }
  }

  case class NonceResponse(nonce: String)
  implicit val nonceFormat: RootJsonFormat[NonceResponse] = jsonFormat1(NonceResponse)


  object PayloadKind extends Enumeration {
    type PayloadKind = Value
    val CSR = Value
  }

  class PayloadKindType extends TypeReference[PayloadKind.type]
  implicit val payloadKindFormat: RootJsonFormat[PayloadKind.PayloadKind] = new EnumJsonConverter(PayloadKind)

  object ReportKind extends Enumeration {
    type ReportKind = Value
    val DCAP = Value
    val SEV_SNP = Value
  }
  class ReportKindType extends TypeReference[ReportKind.type]
  implicit val reportKindFormat: RootJsonFormat[ReportKind.ReportKind] = new EnumJsonConverter(ReportKind)

  case class Payload(
                      value: String,
                      @JsonScalaEnumeration(classOf[PayloadKindType])
                      kind: PayloadKind.PayloadKind
                    )
  implicit val payloadFormat: RootJsonFormat[Payload] = jsonFormat2(Payload)

  sealed class TeeReportValue(blob: String) {
    def getBlob = blob
  }
  object TeeReportValue {
    case class DCAP(quote: String, pck: String, intermediateCA: String) extends TeeReportValue(quote)
    case class SEVSNP(report: String, vekCert: String, intermediateCA: String) extends TeeReportValue(report)
    val dcapFormat = jsonFormat3(DCAP)
    val sevsnpFormat = jsonFormat3(SEVSNP)

  }

  case class TeeReport(
                        value: TeeReportValue,
                        @JsonScalaEnumeration(classOf[ReportKindType])
                        kind: ReportKind.ReportKind
                      )
  implicit def sumFormat:JsonFormat[TeeReport] = new JsonFormat[TeeReport] {
    override def write(sum: TeeReport) = ???
    override def read(value: JsValue): TeeReport = value match {
      case x: JsObject => x.fields.get("kind") match {
        case Some(JsString("DCAP")) => TeeReport(x.fields("value").convertTo[TeeReportValue.DCAP](TeeReportValue.dcapFormat),ReportKind.DCAP)
        case Some(JsString("SEVSNP")) => TeeReport(x.fields("value").convertTo[TeeReportValue.SEVSNP](TeeReportValue.sevsnpFormat),ReportKind.SEV_SNP)
        case Some(JsString(x)) => throw new SerializationException("Unsupported Tee, " + x)
        case _ => throw new SerializationException("Missing or corrupt <kind> field")
      }
      case x => deserializationError("Expected TeeReport as JsObject, but got " + x)
    }
  }

  case class CsrPayload(csr: String, nonce: String)
  implicit val csrPayloadFormat: RootJsonFormat[CsrPayload] = jsonFormat2(CsrPayload)


  case class AttestationStruct(payload: Payload, teeReport: TeeReport, opt: Map[String, String])
  implicit val attestationStructRawFormat: RootJsonFormat[AttestationStruct] = jsonFormat3(AttestationStruct)

  case class NumIssue(code: Int, msg: String)
  implicit val numIssueFormat: RootJsonFormat[NumIssue] = jsonFormat2(NumIssue)

  case class CsrGrant(warnings: Option[Seq[NumIssue]], cert: String)
  implicit val csrGrantFormat: RootJsonFormat[CsrGrant] = jsonFormat2(CsrGrant)

  case class NoGrant(errors: Seq[NumIssue])
  implicit val noGrantFormat: RootJsonFormat[NoGrant] = jsonFormat1(NoGrant)
}

object Err {

  object TripleaIssue extends Enumeration {
    type Type = Value
    protected case class TripleaIssueVal(code: Int, severe: Boolean = false) extends super.Val
    import scala.language.implicitConversions
    implicit def valueToVal(x: Value): TripleaIssueVal = x.asInstanceOf[TripleaIssueVal]

    val PCK_CERT_CHAIN = TripleaIssueVal(1)
    val QE_SIGNATURE = TripleaIssueVal(2)
    val CERT_PARSING = TripleaIssueVal(3)
    val PUB_KEY_PARSING = TripleaIssueVal(4)
    val INVALID_PUB_KEY = TripleaIssueVal(5)
    val UNSUPPORTED_CERT_CHAIN_KEY_TYPE = TripleaIssueVal(6)
    val CORRUPT_QUOTE_REQUEST_PAYLOAD = TripleaIssueVal(7)
    val ENCALVE_IN_DEBUG_MODE = TripleaIssueVal(8, true)
    val MALFORMATTED_QUOTE = TripleaIssueVal(9)
//    val MALFORMATTED_QUOTE_REQUEST = TripleaIssueVal(10)
    val WRONG_NONCE = TripleaIssueVal(11, true)
    val ENCLAVE_SIGNATURE = TripleaIssueVal(12)
    val UNIMPLEMENTED_TODO = TripleaIssueVal(13)
    val POLICY_VIOLATION = TripleaIssueVal(14, true)
    val API_USAGE_BUG = TripleaIssueVal(15, false)
    val SEVSNP_REPORT_SIG = TripleaIssueVal(16)
    val SEVSNP_IN_DEBUG_MODE = TripleaIssueVal(17, true)
  }

  type Issues = Nec[Issue]

  case class Issue(aaaIssue: TripleaIssue.Type, msg: String)

  def issueT[X](code: TripleaIssue.Type, msg: String): Issues Ior X =
    Nec.one(Issue(code, msg)).leftIor

  def issue[X](code: TripleaIssue.Type, msg: String): Either[Issue, X] =
    Left(Issue(code, msg))

  class MTValid[Tag] private(val _unit: Unit) extends AnyVal
  object MTValid {
    def apply[Tag](): MTValid[Tag] = new MTValid(())
  }

  def nonProdValidation[T](result: Issues Ior MTValid[T]): Issues Ior MTValid[T] = {
    result.putRight(MTValid.apply())
  }

}

object Attestation {

  import API._
  import Err._
  import DCAPVerifier.CsrAttestation
//  case class NonceResponse(nonce: String)
//  implicit val saltFormat = jsonFormat1(NonceResponse)
//
//  case class CsrPayload(csr: String, nonce: String)
//  implicit val csrPayloadFormat = jsonFormat2(CsrPayload)
//
//  case class AttestationRequest(payload: String, quote: String, pck: String, intermediateCA: String, opt: Map[String, String])
//  implicit val attestationQuoteRawFormat = jsonFormat5(AttestationRequest)
//

  def validatePayload(aq: AttestationStruct): Issues Ior CsrPayload = {
    Try(aq.payload.value.parseJson.convertTo[CsrPayload]).fold(
      _e => issueT(TripleaIssue.CORRUPT_QUOTE_REQUEST_PAYLOAD,"Can't parse Base64"),
      v => Ior.right(CsrPayload(v.csr,v.nonce))
    )
  }

  def validateAttestationQuoteFormat(aq: AttestationStruct, payload: CsrPayload): Issues Ior CsrAttestation = {
    (Util.validateCsr(payload.csr,TripleaIssue.CORRUPT_QUOTE_REQUEST_PAYLOAD),
      Util.validateB64(aq.teeReport.value.getBlob,TripleaIssue.CORRUPT_QUOTE_REQUEST_PAYLOAD),
      Nonces.validate(payload.nonce)
      ).mapN(CsrAttestation(_, _, aq)(_))
  }

  def teeMismatch: Issues = Nec.one(Issue(TripleaIssue.API_USAGE_BUG,"Wrong TEE"))

  def checkTeeReportFormat(teeReport: TeeReport, expected: ReportKind.ReportKind): Either[RESTError,Unit] =
    Either.cond(teeReport.kind == expected, (), toRESTErrors(teeMismatch)
  )

  private def toNumIssue(issue: Issue) = NumIssue(issue.aaaIssue.code,issue.msg)

  def toRESTErrors(issues: Issues): RESTError = {
    val (bad, bug)= issues.toChain.toList.partition(_.aaaIssue.severe)
    if(bad.nonEmpty) {
      RESTError(StatusCodes.Forbidden,noGrantFormat.write(NoGrant(bad.map(toNumIssue))).toString())
    } else {
      RESTError(StatusCodes.BadRequest,noGrantFormat.write(NoGrant(bug.map(toNumIssue))).toString())
    }
  }
}

class Attestation(grantSignerCert: String, grantSignerKey: String, keyPass: String) {
  import Attestation._
  import API._
  import Err._

  private val csrSigner = new CSRSigner(grantSignerCert,grantSignerKey,keyPass)

  private def todo: Route =
    path("v1" / "attestation" / ("sgx1" | "lite") / ("grant"|"nonce")) {
      complete(StatusCodes.NotImplemented)
    }

  private def init: Route =
    path("v1" / "attestation" / ("dcap" | "sev-snp") / "nonce") {
      get {
        respondWith {
          Right(NonceResponse(Nonces.get().value))
        }
      }
    }

  private def dcap: Route = {

    path("v1" / "attestation" / "dcap" / "grant") {
      clientCerts { certs =>
        post {
          entity(as[API.AttestationStruct]) { attRequest =>
            respondWith {
//              println(attRequest)

              val grant: Either[RESTError, CsrGrant] = for {

                _mismatch <- checkTeeReportFormat(attRequest.teeReport, ReportKind.DCAP)

                jsonPayload <- validatePayload(attRequest).toEither.left.map(toRESTErrors)

                attQuote <- validateAttestationQuoteFormat(attRequest,jsonPayload).toEither.left.map(toRESTErrors)

                verifiedReport <- DCAPVerifier.validate(attQuote).left.map(toRESTErrors)

                validatedCsr <- Policy.validate(verifiedReport,Hostname(attRequest.opt("hostname")),certs).toEither.left.map(toRESTErrors)

                certHolder = csrSigner.sign(validatedCsr)
                pem = Util.makePEM(certHolder)

              } yield CsrGrant(None,pem)
              println(grant)
              grant
            }
          }
        }
      }
    }
  }

  private def sevSNP: Route = {

    path("v1" / "attestation" / "sev-snp" / "grant") {
      clientCerts { certs =>
        post {
          entity(as[API.AttestationStruct]) { attRequest =>
            respondWith {
//              println(attRequest)

              val grant: Either[RESTError, CsrGrant] = for {

                _mismatch <- checkTeeReportFormat(attRequest.teeReport, ReportKind.SEV_SNP)

                jsonPayload <- validatePayload(attRequest).toEither.left.map(toRESTErrors)

                attQuote <- validateAttestationQuoteFormat(attRequest,jsonPayload).toEither.left.map(toRESTErrors)

                verifiedReport <- SEVSNPVerifier.validate(attQuote).left.map(toRESTErrors)

                validatedCsr <- Policy.validate(verifiedReport,Hostname(attRequest.opt("hostname")),certs).toEither.left.map(toRESTErrors)

                certHolder = csrSigner.sign(validatedCsr)
                pem = Util.makePEM(certHolder)

              } yield CsrGrant(None,pem)

              grant
            }
          }
        }
      }
    }
  }

  val routes = concat(init,dcap,sevSNP,todo)
}
