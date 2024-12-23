package cc.multee.triplea

import Err._
import cats.data.Ior

import scala.collection.mutable.Set
import java.security.SecureRandom

case class Nonce(value: String) extends AnyVal

object Nonces {

  private val prng = new SecureRandom()

  private val issued: Set[Nonce] = Set()

  def get(): Nonce = {
    val r = rndBytes(16)
    issued.add(r)
    r
  }

  def validate(nonce: String): Issues Ior MTValid[Nonce] = {
    if( issued.remove(Nonce(nonce))) {
      Ior.right(MTValid())
    } else {
      issueT(TripleaIssue.WRONG_NONCE, "Unrecognized nonce")
    }
  }

  private def rndBytes(bytesNum: Int) = {
    val buf = new Array[Byte](bytesNum)
    prng.nextBytes(buf)
    Nonce(Util.toB64(buf))
  }
}
