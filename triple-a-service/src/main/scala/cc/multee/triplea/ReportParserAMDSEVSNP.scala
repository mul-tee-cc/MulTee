package cc.multee.triplea

import Err.Issue
import Err.issue
import Err.TripleaIssue
import org.bouncycastle.asn1.{ASN1Encodable, ASN1Integer, DERSequence}
import scodec.bits.{BitVector, ByteVector}

import java.math.BigInteger

object ReportParserAMDSEVSNP {

  import scodec.Codec
  import scodec.codecs._

  private val ID_BLK_FAMILY_ID_BYTES = 16;
  private val ID_BLK_IMAGE_ID_BYTES = 16;
  private val ID_BLK_DIGEST_BYTES = 48;

  case class TcbVersion( boot_loader: Int,
                         tee: Int,
                         reserved: ByteVector,
                         snp: Int,
                         microcode: Int)
  private val tcbVersionCodec: Codec[TcbVersion] = (uint8 :: uint8 :: bytes(4) :: uint8 :: uint8).as[TcbVersion]

  case class BuildVersion( build: Int,
                           minor: Int,
                           major: Int,
                           reserved: Int)
  private val buildVersionCodec: Codec[BuildVersion] = (uint8 :: uint8 :: uint8 :: uint8).as[BuildVersion]

  case class Signature( r: ByteVector,
                        s: ByteVector) {
    val toDER = new DERSequence(Array[ASN1Encodable](new ASN1Integer(new BigInteger(r.toArray)),new ASN1Integer(new BigInteger(s.toArray)))).getEncoded
  }
  private val signatureCodec: Codec[Signature] = (bytes(72) :: bytes(72)).as[Signature]

  case class Flags( reserved: BitVector,
                    signingKey: BitVector,
                    maskChip: BitVector,
                    authorKey: BitVector)
  private val flagsCodec: Codec[Flags] = (bits(27) :: bits(3) :: bits(1) :: bits(1)).as[Flags]

  case class Policy( reserved: BitVector,
                     ciphertextHiding: Boolean,
                     raplDisable: Boolean,
                     memAes256XTS: Boolean,
                     cxlAllow: Boolean,
                     singleSocket: Boolean,
                     debug: Boolean,
                     migrationAgent: Boolean,
                     reserved2: BitVector,
                     smt: Boolean,
                     abiMajor: Int,
                     abiMinor: Int,
                   )
  private val policyCodec: Codec[Policy] = (bits(39) :: bool(1) :: bool(1) :: bool(1) :: bool(1) :: bool(1) :: bool(1) :: bool(1) :: bits(1) :: bool(1) :: uint8 :: uint8).as[Policy]

  case class PlatformInfo( reserved: BitVector,
                           ciphertextHiding: Boolean,
                           raplDisable: Boolean,
                           ecc: Boolean,
                           tsme: Boolean,
                           smt: Boolean,
                   )
  private val platformInfoCodec: Codec[PlatformInfo] = (bits(59) :: bool(1) :: bool(1) :: bool(1) :: bool(1) :: bool(1)).as[PlatformInfo]

  case class BodySEVSNP( version: Long,
                         guest_svn: Long,
                         policy: Policy,
                         family_id: ByteVector,
                         image_id: ByteVector,
                         vmpl: Long,
                         signature_algo: Long,
                         platform_version: TcbVersion,
                         platform_info: PlatformInfo,
                         flags: Flags,
                         reserved0: Long,
                         report_data: ByteVector,
                         measurement: ByteVector,
                         host_data: ByteVector,
                         id_key_digest: ByteVector,
                         author_key_digest: ByteVector,
                         report_id: ByteVector,
                         report_id_ma: ByteVector,
                         reported_tcb: TcbVersion,
                         cpuFamily: Int,
                         cpuModel: Int,
                         cpuStepping: Int,
                         reserved1: ByteVector,
                         chip_id: ByteVector,
                         committed_tcb: TcbVersion,
                         current_build: BuildVersion,
                         committed_build: BuildVersion,
                         launch_tcb: TcbVersion,
                         reserved2: ByteVector
                       ) {
    def toBytes: Array[Byte] = sevsnpBodyCodec.encode(this).toOption.get.toByteArray
  }
  private val sevsnpBodyCodec: Codec[BodySEVSNP] = (uint32L :: uint32L :: policyCodec :: bytes(ID_BLK_FAMILY_ID_BYTES) ::
    bytes(ID_BLK_IMAGE_ID_BYTES) :: uint32L :: uint32L :: tcbVersionCodec :: platformInfoCodec :: flagsCodec :: uint32L ::
    bytes(64) :: bytes(ID_BLK_DIGEST_BYTES) :: bytes(32) :: bytes(48) :: bytes(48) :: bytes(32) :: bytes(32) ::
    tcbVersionCodec :: uint8 :: uint8 :: uint8 :: bytes(21) :: bytes(64) :: tcbVersionCodec :: buildVersionCodec ::
    buildVersionCodec :: tcbVersionCodec :: bytes(168)
    ).as[BodySEVSNP]

  case class ReportSEVSNP( body: BodySEVSNP,
                           signature: Signature,
                           reserved: ByteVector
                         )
  private val sevsnpCodec: Codec[ReportSEVSNP] = (sevsnpBodyCodec :: signatureCodec :: bytes(368)).as[ReportSEVSNP]

  def parse(b: Array[Byte]): Either[Issue,ReportSEVSNP] =
    sevsnpCodec.decode(BitVector(b)).toEither match {
      case Left(e) => {
        println(e)
        issue(TripleaIssue.MALFORMATTED_QUOTE,e.messageWithContext)
      }
      case Right(r) if r.remainder.isEmpty => Right(r.value)
      case Right(r) => issue(TripleaIssue.MALFORMATTED_QUOTE,s"Unable to parse message, ${r.remainder.size}B/b remain after pasing")
    }
}
