package cc.multee.triplea

import akka.actor.ActorSystem
import akka.http.scaladsl.HttpsConnectionContext
import akka.http.scaladsl.server.Route

import scala.concurrent.Await
import scala.concurrent.duration._
import scala.language.postfixOps


object App {

  private val ver = "0.7.0"

  def main( args: Array[String] ): Unit =
    args match {
      case Array(tlsKeyStore,identityCa,grantSignerCert,grantSignerKey) => {
        val tls = Util.getCert(tlsKeyStore,"changeit",identityCa)
        val att = new Attestation(Util.readFile(grantSignerCert), Util.readFile(grantSignerKey), "changeit")

        start(att.routes,tls)
      }
      case _ => {

        println("Use: java -jar triple-a-service.jar <web-app-tls.p12> <identity-trust-ca.pem> <grant-signer-cert.pem> <grant-signer-key.pem>")
      }
    }

  private def start(routes: Route, tls: HttpsConnectionContext): Unit = {
    val system = ActorSystem()
    val apiServerF = APIServer(routes,tls)(system)

    val startupDelay = 15 seconds

    Await.result(apiServerF, startupDelay)
    Await.ready(system.whenTerminated, Duration.Inf)

  }
}
