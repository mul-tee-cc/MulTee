package cc.multee.triplea

import Err.Issue
import Err.issue
import Err.TripleaIssue
import org.bouncycastle.asn1.{ASN1Encodable, ASN1Integer, DERSequence}
import scodec.bits.{BitVector, ByteVector}

import java.math.BigInteger

object QuoteParserIntelDCAP {

  import scodec.Codec
  import scodec.codecs._

  private val SGX_REPORT_BODY_RESERVED1_BYTES = 12;
  private val SGX_REPORT_BODY_RESERVED2_BYTES = 32;
  private val SGX_REPORT_BODY_RESERVED3_BYTES = 32;
  private val SGX_REPORT_BODY_RESERVED4_BYTES = 42;
  private val SGX_CPUSVN_SIZE = 16;
  private val SGX_REPORT_DATA_SIZE = 64;
  private val SGX_ISVEXT_PROD_ID_SIZE = 16;
  private val SGX_ISV_FAMILY_ID_SIZE = 16;
  private val SGX_CONFIGID_SIZE = 64;
  private val SGX_HASH_SIZE = 32;

  case class SgxQuoteUserData(qe_id: ByteVector, rest: ByteVector)
  private val sgxQuoteUserDataCodec: Codec[SgxQuoteUserData] = (bytes(16) :: bytes(4)).as[SgxQuoteUserData]

  case class SgxQuoteHeader( version: Int,
                             att_key_type: Int,
                             att_key_data_0: Long,
                             qe_svn: Int,
                             pce_svn: Int,
                             vendor_id: ByteVector,
                             user_data: SgxQuoteUserData
                           ) {
    def toBytes: Array[Byte] = sgxQuoteHeaderCodec.encode(this).toOption.get.toByteArray
  }
  private val sgxQuoteHeaderCodec: Codec[SgxQuoteHeader] = (uint16L :: uint16L :: uint32L :: uint16L :: uint16L :: bytes(16) :: sgxQuoteUserDataCodec).as[SgxQuoteHeader]


  case class SgxAttributes(flags: Long, xfrm: ByteVector)
  private val sgxAttributesCodec: Codec[SgxAttributes] = (longL(64) :: bytes(8)).as[SgxAttributes]

  case class SgxReportBody( cpu_svn: ByteVector,
                            misc_select: Long,
                            reserved1: ByteVector,
                            isv_ext_prod_id: ByteVector,
                            attributes: SgxAttributes,
                            mr_enclave: ByteVector,
                            reserved2: ByteVector,
                            mr_signer: ByteVector,
                            reserved3: ByteVector,
                            config_id: ByteVector,
                            isv_prod_id: Int,
                            isv_svn: Int,
                            config_svn: Int,
                            reserved4: ByteVector,
                            isv_family_id: ByteVector,
                            report_data: ByteVector) {
    def toBytes: Array[Byte] = sgxReportBodyCodec.encode(this).toOption.get.toByteArray
  }
  private val sgxReportBodyCodec: Codec[SgxReportBody] = (
    bytes(SGX_CPUSVN_SIZE) :: uint32L :: bytes(SGX_REPORT_BODY_RESERVED1_BYTES) ::
    bytes(SGX_ISVEXT_PROD_ID_SIZE) :: sgxAttributesCodec :: bytes(SGX_HASH_SIZE) :: bytes(SGX_REPORT_BODY_RESERVED2_BYTES) ::
    bytes(SGX_HASH_SIZE) :: bytes(SGX_REPORT_BODY_RESERVED3_BYTES) ::
    bytes(SGX_CONFIGID_SIZE) :: uint16L :: uint16L :: uint16L :: bytes(SGX_REPORT_BODY_RESERVED4_BYTES) ::
    bytes(SGX_ISV_FAMILY_ID_SIZE) :: bytes(SGX_REPORT_DATA_SIZE)
  ).as[SgxReportBody]

  case class EcdsaSignature(r: ByteVector, s: ByteVector) {
    val toDER = new DERSequence(Array[ASN1Encodable](new ASN1Integer(new BigInteger(r.toArray)),new ASN1Integer(new BigInteger(s.toArray)))).getEncoded
  }
  private val sgxEcdsaSignatureCodec: Codec[EcdsaSignature] = (bytes(32) :: bytes(32)).as[EcdsaSignature]

  case class SgxQlEcdsaSigData( sig: EcdsaSignature,
                                attest_pub_key: ByteVector,
                                qe_report: SgxReportBody,
                                qe_report_sig: EcdsaSignature)
  private val sgxQlEcdsaSigDataCodec: Codec[SgxQlEcdsaSigData] = (sgxEcdsaSignatureCodec :: bytes(64) :: sgxReportBodyCodec :: sgxEcdsaSignatureCodec).as[SgxQlEcdsaSigData]

  case class AuthCertificationData(size: Int, auth_data: ByteVector)
  private val authTupleCodec: Codec[(Int, ByteVector)] = ("size" | uint16L).flatZip { l => "auth_data" | bytes(32) }
  private val authCertificationDataCodec: Codec[AuthCertificationData] = authTupleCodec.xmap({ (a, b) => AuthCertificationData(a, b) }, { z => z.size -> z.auth_data })

  case class SgxQlCertificationData(cert_key_type: Int, size: Long)
  private val sgxQlCertificationDataCodec: Codec[SgxQlCertificationData] = (uint16L :: uint32L).as[SgxQlCertificationData]

  case class SgxQuote3( header: SgxQuoteHeader,
                        report_body: SgxReportBody,
                        signature_data_len: Long,
                        sig_data: SgxQlEcdsaSigData,
                        auth_certification_data: AuthCertificationData,
                        sgx_ql_certification_data: SgxQlCertificationData)
  val sgxQuote3Codec: Codec[SgxQuote3] = (sgxQuoteHeaderCodec :: sgxReportBodyCodec :: uint32L :: sgxQlEcdsaSigDataCodec :: authCertificationDataCodec :: sgxQlCertificationDataCodec).as[SgxQuote3]

  def parse(b: Array[Byte]): Either[Issue,SgxQuote3] =
    sgxQuote3Codec.decode(BitVector(b)).toEither match {
      case Left(e) => issue(TripleaIssue.MALFORMATTED_QUOTE,e.messageWithContext)
      case Right(r) if r.remainder.isEmpty => Right(r.value)
      case Right(r) => issue(TripleaIssue.MALFORMATTED_QUOTE,s"Unable to parse message, ${r.remainder.size}B/b remain after pasing")
    }
}
