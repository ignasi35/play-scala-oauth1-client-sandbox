package controllers

import java.nio.ByteBuffer
import java.security.InvalidKeyException
import java.util.concurrent.ThreadLocalRandom

import javax.inject._
import play.api.libs.oauth.{ ConsumerKey, OAuthCalculator, RequestToken }
import play.api.libs.ws.{ WSClient, WSRequest, WSResponse }
import play.api.mvc._
import play.shaded.ahc.org.asynchttpclient.Param
import play.shaded.ahc.org.asynchttpclient.uri.Uri
import play.shaded.ahc.org.asynchttpclient.util.HttpConstants.Methods

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


  def index() = Action { implicit request =>

    val testUrl = urlBase + "/workflows/subscription/"

    val requestToken: RequestToken = RequestToken(null, null)
    val consumerKey: ConsumerKey = ConsumerKey(apiKey, secretKey)

    val authRequest = withQueryStringOauth(testUrl, consumerKey, requestToken)
    val eventualResponse: Future[WSResponse] = authRequest.get()

    Ok(Await.result(eventualResponse, 30.seconds).body)
  }


  private def withQueryStringOauth(
                                    url: String,
                                    consumerAuth: ConsumerKey,
                                    userAuth: RequestToken): WSRequest = {

    // Computes the signature
    val (signature, nonce, timestamp) = new OAuthSignatureCalculatorInstance().computeSignature(
      consumerAuth,
      userAuth,
      Uri.create(url),
      Methods.GET
    )


    // Builds a PlayWS request with all the query parameters and signature
    ws.url(url)
      .withQueryStringParameters(
        OAuthSignatureCalculatorInstance.KEY_OAUTH_SIGNATURE -> signature,
        OAuthSignatureCalculatorInstance.KEY_OAUTH_SIGNATURE_METHOD  -> OAuthSignatureCalculatorInstance.OAUTH_SIGNATURE_METHOD,
        OAuthSignatureCalculatorInstance.KEY_OAUTH_CONSUMER_KEY -> consumerAuth.key,
        OAuthSignatureCalculatorInstance.KEY_OAUTH_NONCE  -> nonce,
        OAuthSignatureCalculatorInstance.KEY_OAUTH_TIMESTAMP  -> timestamp.toString,
        OAuthSignatureCalculatorInstance.KEY_OAUTH_VERSION  -> OAuthSignatureCalculatorInstance.OAUTH_VERSION_1_0
      )
  }

  def echo() = Action { implicit request =>

    println(request.headers)
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
