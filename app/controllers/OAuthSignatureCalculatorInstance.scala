package controllers

/*
This is transcribed and adapted from
https://raw.githubusercontent.com/AsyncHttpClient/async-http-client/master/client/src/main/java/org/asynchttpclient/oauth/OAuthSignatureCalculatorInstance.java
 */

/*
 * Copyright (c) 2017 AsyncHttpClient Project. All rights reserved.
 *
 * This program is licensed to you under the Apache License Version 2.0,
 * and you may not use this file except in compliance with the Apache License Version 2.0.
 * You may obtain a copy of the Apache License Version 2.0 at
 *     http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the Apache License Version 2.0 is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the Apache License Version 2.0 for the specific language governing permissions and limitations there under.
 */

import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets.UTF_8
import java.security.InvalidKeyException
import java.util
import java.util.Base64
import java.util.concurrent.ThreadLocalRandom
import java.util.regex.Pattern

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import play.api.libs.oauth.{ ConsumerKey, RequestToken }
import play.shaded.ahc.org.asynchttpclient.Param
import play.shaded.ahc.org.asynchttpclient.uri.Uri
import play.shaded.ahc.org.asynchttpclient.util.{ StringBuilderPool, StringUtils, Utf8UrlEncoder }

import scala.collection.mutable

/**
  * Non thread-safe {@link SignatureCalculator} for OAuth1.
  * <p>
  * Supports most common signature inclusion and calculation methods: HMAC-SHA1 for calculation, and Header inclusion as inclusion method. Nonce generation uses simple random
  * numbers with base64 encoding.
  */
object OAuthSignatureCalculatorInstance {
  private val STAR_CHAR_PATTERN = Pattern.compile("*", Pattern.LITERAL)
  private val PLUS_CHAR_PATTERN = Pattern.compile("+", Pattern.LITERAL)
  private val ENCODED_TILDE_PATTERN = Pattern.compile("%7E", Pattern.LITERAL)
 val KEY_OAUTH_CONSUMER_KEY = "oauth_consumer_key"
 val KEY_OAUTH_NONCE = "oauth_nonce"
 val KEY_OAUTH_SIGNATURE = "oauth_signature"
 val KEY_OAUTH_SIGNATURE_METHOD = "oauth_signature_method"
 val KEY_OAUTH_TIMESTAMP = "oauth_timestamp"
 val KEY_OAUTH_TOKEN = "oauth_token"
 val KEY_OAUTH_VERSION = "oauth_version"
   val OAUTH_VERSION_1_0 = "1.0"
   val OAUTH_SIGNATURE_METHOD = "HMAC-SHA1"
  private val HMAC_SHA1_ALGORITHM = "HmacSHA1"

  case class Parameter(key: String, value: String)

  private def getPercentEncoded(in: String) = Utf8UrlEncoder.percentEncodeQueryElement(in);

  // This is https://github.com/AsyncHttpClient/async-http-client/blob/master/client/src/main/java/org/asynchttpclient/oauth/Parameters.java#L35
  def sortAndConcat(parameters: mutable.Buffer[Parameter]): String = { // then sort them (AFTER encoding, important)
    val sorted = parameters.sortWith{
      (p1,p2) => if(p1.key==p2.key) p1.value<p2.value else p1.key<p2.key
    }
    sorted.map(p => s"${p.key}=${p.value}").mkString("&")
  }

}

class OAuthSignatureCalculatorInstance() {

  import OAuthSignatureCalculatorInstance._

  private val HMAC_SHA1_ALGORITHM = "HmacSHA1"
  private final val mac = Mac.getInstance(OAuthSignatureCalculatorInstance.HMAC_SHA1_ALGORITHM)

  private def generateNonce = {
    val nonceBuffer = new Array[Byte](16)
    ThreadLocalRandom.current.nextBytes(nonceBuffer)
    Base64.getEncoder.encodeToString(nonceBuffer)
  }

  private def generateTimestamp = System.currentTimeMillis / 1000L

  @throws[InvalidKeyException]
  def computeSignature(
                        consumerAuth: ConsumerKey,
                        userAuth: RequestToken,
                        uri: Uri,
                        method: String): (String, String, Long) = {
    val timestamp = generateTimestamp
    val nonce = generateNonce
    val signature = privateComputeSignature(consumerAuth,
      userAuth,
      uri,
      method,
      new util.ArrayList[Param](0),
      new util.ArrayList[Param](0),
      timestamp,
      nonce
    )
    (signature, nonce, timestamp)
  }

  @throws[InvalidKeyException]
  private def privateComputeSignature(
                                consumerAuth: ConsumerKey,
                                userAuth: RequestToken,
                                uri: Uri,
                                method: String,
                                formParams: java.util.List[Param],
                                queryParams: java.util.List[Param],
                                oauthTimestamp: Long,
                                percentEncodedNonce: String): String = {
    val sb = signatureBaseString(consumerAuth, userAuth, uri, method, formParams, queryParams, oauthTimestamp, percentEncodedNonce)
    val rawBase: ByteBuffer = StringUtils.charSequence2ByteBuffer(sb, UTF_8)
    val rawSignature = digest(consumerAuth, userAuth, rawBase)
    // and finally, base64 encoded... phew!
    val signature = Base64.getEncoder.encodeToString(rawSignature)
    signature
  }

  def signatureBaseString(consumerAuth: ConsumerKey,
                          userAuth: RequestToken,
                          uri: Uri,
                          method: String,
                          formParams: java.util.List[Param],
                          queryParams: java.util.List[Param],
                          oauthTimestamp: Long,
                          percentEncodedNonce: String): java.lang.StringBuilder = { // beware: must generate first as we're using pooled StringBuilder
    val baseUrl = uri.toBaseUrl
    val encodedP = encodedParams(consumerAuth, userAuth, oauthTimestamp, percentEncodedNonce, formParams, queryParams)
    val sb = StringBuilderPool.DEFAULT.stringBuilder
    sb.append(method) // POST / GET etc (nothing to URL encode)

    sb.append('&')
    Utf8UrlEncoder.encodeAndAppendPercentEncoded(sb, baseUrl)
    // and all that needs to be URL encoded (... again!)
    sb.append('&')
    Utf8UrlEncoder.encodeAndAppendPercentEncoded(sb, encodedP)
    sb
  }

  import play.shaded.ahc.org.asynchttpclient.util.Utf8UrlEncoder


  private def encodedParams(consumerAuth: ConsumerKey,
                            userAuth: RequestToken,
                            oauthTimestamp: Long,
                            percentEncodedNonce: String,
                            formParams: java.util.List[Param],
                            queryParams: java.util.List[Param]) = {
    val parameters: mutable.Buffer[Parameter] = mutable.Buffer.empty[Parameter]
    // List of all query and form parameters added to this request; needed for calculating request signature
    // Start with standard OAuth parameters we need
    parameters += Parameter(KEY_OAUTH_CONSUMER_KEY, getPercentEncoded(consumerAuth.key))
    parameters += Parameter(KEY_OAUTH_NONCE, percentEncodedNonce)
    parameters += Parameter(KEY_OAUTH_SIGNATURE_METHOD, OAUTH_SIGNATURE_METHOD)
    parameters += Parameter(KEY_OAUTH_TIMESTAMP, String.valueOf(oauthTimestamp))
    if (userAuth.token != null)
      parameters += Parameter(KEY_OAUTH_TOKEN, getPercentEncoded(userAuth.token))
    parameters += Parameter(KEY_OAUTH_VERSION, OAUTH_VERSION_1_0)
    if (formParams != null) {
      import scala.collection.JavaConversions._
      for (param <- formParams) { // formParams are not already encoded
        parameters += Parameter(Utf8UrlEncoder.percentEncodeQueryElement(param.getName), Utf8UrlEncoder.percentEncodeQueryElement(param.getValue))
      }
    }
    if (queryParams != null) {
      import scala.collection.JavaConversions._
      for (param <- queryParams) { // queryParams are already form-url-encoded
        // but OAuth1 uses RFC3986_UNRESERVED_CHARS so * and + have to be encoded
        parameters += Parameter(percentEncodeAlreadyFormUrlEncoded(param.getName), percentEncodeAlreadyFormUrlEncoded(param.getValue))
      }
    }
    sortAndConcat(parameters)
  }

  private def percentEncodeAlreadyFormUrlEncoded(s: String) = {
    val s1 = STAR_CHAR_PATTERN.matcher(s).replaceAll("%2A")
    val s2 = PLUS_CHAR_PATTERN.matcher(s1).replaceAll("%20")
    ENCODED_TILDE_PATTERN.matcher(s2).replaceAll("~")
  }

  @throws[InvalidKeyException]
  private def digest(consumerAuth: ConsumerKey,
                     userAuth: RequestToken,
                     message: ByteBuffer) = {
    val sb = StringBuilderPool.DEFAULT.stringBuilder
    Utf8UrlEncoder.encodeAndAppendQueryElement(sb, consumerAuth.secret)
    sb.append('&')
    if (userAuth != null && userAuth.secret != null) Utf8UrlEncoder.encodeAndAppendQueryElement(sb, userAuth.secret)
    val keyBytes = StringUtils.charSequence2Bytes(sb, UTF_8)
    val signingKey = new SecretKeySpec(keyBytes, HMAC_SHA1_ALGORITHM)
    synchronized {
      mac.init(signingKey)
      mac.reset
      mac.update(message)
      mac.doFinal
    }
  }
}