package controllers

import java.time.Instant

import javax.inject._
import play.api._
import play.api.http.HeaderNames
import play.api.libs.oauth.{ ConsumerKey, OAuthCalculator, RequestToken }
import play.api.mvc._
import play.api.libs.ws.{ WSClient, WSRequestExecutor, WSResponse }

import scala.concurrent.duration._
import scala.concurrent.{ Await, Future }

/**
  * This controller creates an `Action` to handle HTTP requests to the
  * application's home page.
  */
@Singleton
class HomeController @Inject()(ws: WSClient, cc: ControllerComponents) extends AbstractController(cc) {


  val urlBase = "http://localhost:9000/echo"
  val apiKey = "1234"
  val secretKey = "qwer"

  val KEY = ConsumerKey(apiKey, secretKey)

  def index() = Action { implicit request =>

    val testUrl = urlBase + "/workflows/subscription/"
    val plainRequest = ws
      .url(testUrl)
      .withHttpHeaders(
        // no need to set headers because OAuthCalculator + RequestFilter will create them already.
      )
    val requestToken: RequestToken = RequestToken(null, null)
    val authRequest =
      plainRequest
        .sign(OAuthCalculator(KEY, requestToken))
        .withRequestFilter(headerToQueryStringOAuthFilter)
    val eventualResponse: Future[WSResponse] = authRequest.get()

    Ok(Await.result(eventualResponse, 30.seconds).body)
  }

  private def headerToQueryStringOAuthFilter(executor: WSRequestExecutor): WSRequestExecutor =
    WSRequestExecutor { request =>
      // extract the OAuth signature and parameters from the "Authorization" header and rewrite the queryString.
      executor {
        request.header(HeaderNames.AUTHORIZATION).map { authHeader =>
          print("[CLIENT Filter] Using filtered request")
          request.withQueryStringParameters("newParam" -> "newValue")
        }.getOrElse{
          println("[CLIENT Filter] No Authorization header found.")
          request
        }
      }
    }


  def echo() = Action { implicit request =>

    println("[SERVER] request: "+ request)
    println("[SERVER] queryString: "+ request.queryString)
    println("[SERVER] Authorization: "+ request.headers(HeaderNames.AUTHORIZATION))
    // HEADERS:
    //    List(
    //      (Remote-Address,127.0.0.1:56949),
    //    (Raw-Request-URI,/echo/workflows/subscription/?
    //      oauth_consumer_key=1234&
    //      oauth_signature_method=HMAC-SHA1&
    //      oauth_nonce=1538557680&         // <-- this is ignored
    //      oauth_timestamp=1538557680),    // <-- this is ignored
    //    (Tls-Session-Info,[Session-1, SSL_NULL_WITH_NULL_NULL]),
    //    (Authorization,OAuth
    //      oauth_consumer_key="1234",
    //      oauth_signature_method="HMAC-SHA1",
    //      oauth_signature="in%2BGSWU079ougvcL0tQQmwx2eGg%3D",
    //      oauth_timestamp="1538557698",                  // <-- computed internally (used debugger to force a pause)
    //      oauth_nonce="rVnVZPhpF4Ak7zX1PxtaEQ%3D%3D",    // <-- this is a really random nonce
    //      oauth_version="1.0"),
    //    (Host,localhost:9000), (Accept,*/*),
    //    (User-Agent,AHC/2.0),
    //    (Timeout-Access,<function1>)
    //    )
    Ok("")
  }
}
