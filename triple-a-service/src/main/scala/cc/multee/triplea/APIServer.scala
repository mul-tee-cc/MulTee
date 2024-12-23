package cc.multee.triplea

import akka.actor.ActorSystem
import akka.http.scaladsl.marshallers.sprayjson.SprayJsonSupport
import akka.http.scaladsl.marshalling.ToEntityMarshaller
import akka.http.scaladsl.model._
import akka.http.scaladsl.model.headers.{ProductVersion, Server}
import akka.http.scaladsl.server._
import akka.http.scaladsl.settings.ServerSettings
import akka.http.scaladsl.{Http, HttpsConnectionContext}
import cats.data.EitherT

import java.security.cert.Certificate
import scala.concurrent.Future
import scala.util.{Failure, Success}

object APIServer extends Directives with SprayJsonSupport {

  private[triplea] case class RESTError(statusCode: StatusCode, msg: String)

  private[triplea] implicit val ec: scala.concurrent.ExecutionContext = scala.concurrent.ExecutionContext.global

  private[triplea] def clientCerts: Directive1[Array[Certificate]] =
    extractRequest.map( request => request.attribute(AttributeKeys.sslSession).get.session.getPeerCertificates )

  private[triplea] def respondWith[X](value: => Either[RESTError,X])(implicit m: ToEntityMarshaller[X]): Route =
    respond(Future(value))

  private[triplea] def respondWithF[X](value: => EitherT[Future,RESTError,X])(implicit m: ToEntityMarshaller[X]): Route =
    respond(value.value)

  private def respond[X](value: Future[Either[RESTError,X]])(implicit m: ToEntityMarshaller[X]): Route =
    onComplete(value) {
      case Success(Right(())) => complete(StatusCodes.OK)
      case Success(Right(r)) => complete(StatusCodes.OK -> r)
      case Success(Left(e)) => complete(e.statusCode -> e.msg)
      case Failure(exception) => {
        exception.printStackTrace()
        complete(StatusCodes.InternalServerError -> exception.toString)
      }
    }

  def apply(routes: Route, tls: HttpsConnectionContext)(implicit system: ActorSystem) = {

    val interface = "0.0.0.0"
    val port = 2443

    val settings = ServerSettings(system).withServerHeader(Some(Server(
      List(ProductVersion("Triple-A Server", "0.7.0")))))

    val bindingFuture = Http().newServerAt(interface, port).enableHttps(tls).withSettings(settings).bind(routes)
    println(s"Triple-A Server is listening on https://$interface:$port")
    bindingFuture
  }
}


