package com.foggystreet.oauth2.api;

import java.io.File;
import java.net.URI;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;

import javax.net.ssl.SSLContext;
import javax.servlet.http.HttpServletRequest;

import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.conn.ssl.NoopHostnameVerifier;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.ssl.TrustStrategy;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;

import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.howe.helper.StringCheck;
import com.howe.login.command.TokenFactory;
import com.howe.startup.FoggyStreetHome;
import com.howe.startup.type.ApplicationConfig;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;

/**
 * @Copyright 2019 Andrew Howe All rights reserved, this software may not be
 *            reproduced or distributed in whole or in part in any manner
 *            without the permission of the copyright owner.
 * 
 *            THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 *            EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 *            MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 *            NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 *            HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 *            WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *            OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *            DEALINGS IN THE SOFTWARE.
 *          
 *            
 *            
 *            Helper class to perform the Validation of the Token and 
 *            methods to perform the REST calls to the OAuth server.
 *            
 *            The following variables should be set before using this class
 *            
 *   JWTTokenFactory.setOauthApplicationID(..);
	 JWTTokenFactory.setOauthAuthenticationURL(..);
	 JWTTokenFactory.setOauthTokenURL(..);
	 JWTTokenFactory.setOauthTokenInfoURL(..);
	 JWTTokenFactory.setOauthUserInfoURL(..);
	 JWTTokenFactory.setPublicKeyPath(..); 
	 JWTTokenFactory.setClientID(..);
	 JWTTokenFactory.setClientSecret(..); 
	 JWTTokenFactory.setRedirectURL(..);
	 
	 The developer should set these values once at application startup.
	 
 **/

public class JWTTokenFactory {

	private static final ObjectMapper mapper = new ObjectMapper();
	public static final String AUTH_HEADER = "Authorization";
	public static final String AUTH_HEADER_BEARER = "Bearer";
	public static final String AUTH_HEADER_BEARER_LOWER = "bearer";
	public static final String AUTH_HEADER_BEARER_UPPER = "BEARER";
	private static final String KEYS_JOBS = "keys";
	private static final String AUTH_PUBLIC_KEY_FILENAME = "authPublic.pkcs8";
	private static final int CODE_CHALLENGE_MIN_LENGTH = 43;
	private static final int CODE_CHALLENGE_MAX_LENGTH = 128;
	
	/**
	 * Oauth2 Code Challenge method type - plain
	 * 
	 * The code challenge is not hashed
	 */
	public static final String CODE_CHALLENGE_METHOD_PLAIN = "plain";
	
	/**
	 * Oauth2 Code Challenge method type - S256
	 * 
	 * The code challenge is hashed using S256 
	 * 
	 * Use helper method    JWTTokenFactory.createS256CodeChallenge(..)
	 * 
	 * to create the code challenge string 
	 */
	public static final String CODE_CHALLENGE_METHOD_S256 = "s256";

	
	private static String pathPublicKey;
	private static String oauthApplicationID;
	private static String oauthAuthenticationURL;
	private static String oauthTokenURL;
	private static String oauthTokenInfoURL;
	private static String oauthUserInfoURL;
	private static String clientID;
	private static String clientSecret;
	private static String redirectURL;
	
	/**
	 * Set the OAuth redirectURL that will bet sent to the Auth server
	 * 
	 * This URL will be the URL of your Application callback REST end point
	 * 
	 * @param redirectURL
	 */
	public static void setRedirectURL(String redirectURL) {
		JWTTokenFactory.redirectURL = redirectURL;
	}

	/**
	 * Location of the Public Key file authPublic.pkcs8 on your 
	 * hard drive.  The file is obtained from the FoggyStreet OAuth server
	 * under the FOGGY_OAUTH_HOME/keys  directory.
	 * 
	 * @param aPath
	 */
	public static void setPublicKeyPath(String aPath) {
		pathPublicKey = aPath;
	}

	/**
	 * Set the ApplicationID of this server, this value must match the
	 * ID set in the FoggyStreet OAuth server.
	 * 
	 * @param anOauthApplicationID
	 */
	public static void setOauthApplicationID(String anOauthApplicationID) {
		JWTTokenFactory.oauthApplicationID = anOauthApplicationID;
	}

	public static String getOauthApplicationID() {
		return JWTTokenFactory.oauthApplicationID;
	}
	
	/**
	 * Set the URL of the FoggyStreet URL to the /token URL
	 * 
	 * This endpoint will create the Token and normally handles
	 * the grant_types authorization_code or reqeust_token etc.
	 * 
	 * The value should be:
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/token
	 *  
	 * @param aOauthTokenURL
	 */
	public static void setOauthTokenURL(String aOauthTokenURL) {
		JWTTokenFactory.oauthTokenURL = aOauthTokenURL;
	}

	/**
	 * Set the URL of the FoggyStreet URL to the /userinfo URL
	 * 
	 * This endpoint returns information about the token.
	 * i.e if its revoked or valid etc.
	 * 
	 * The value should be:
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/tokeninfo
	 *  
	 * @param aOauthTokenURL
	 */
	public static void setOauthUserInfoURL(String aOauthUserInfoURL) {
		JWTTokenFactory.oauthUserInfoURL = aOauthUserInfoURL;
	}
	
	/**
	 * Set the URL of the FoggyStreet URL to the /tokeninfo URL
	 * 
	 * This endpoint returns information about the token.
	 * i.e if its revoked or valid etc.
	 * 
	 * The value should be:
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/tokeninfo
	 *  
	 * @param aOauthTokenURL
	 */
	public static void setOauthTokenInfoURL(String aOauthTokenInfoURL) {
		JWTTokenFactory.oauthTokenInfoURL = aOauthTokenInfoURL;
	}
	
	/**
	 * Set the URL of the FoggyStreet URL to the /auth URL
	 * 
	 * This endpoint is the first call into the OAuth server sending in the fields
	 * 
	 *  response_type
	 * 	client_id
		redirect_uri
		scope
		state
		
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 *  
	 * @param aOauthTokenURL
	 */
	public static void setOauthAuthenticationURL(String oauthAuthURL) {
		JWTTokenFactory.oauthAuthenticationURL = oauthAuthURL;
	}
	
	/**
	 * Set the ClientID of the server, this value is obtained 
	 * from the FoggyStreet OAuth server when an Application is 
	 * created.
	 * 
	 * Please contact Admin or App owner to get the Client ID.
	 * 
	 * @param clientID
	 */
	public static void setClientID(String clientID) {
		JWTTokenFactory.clientID = clientID;
	}

	/**
	 * Set the ClientSecret of the server, this value is obtained 
	 * from the FoggyStreet OAuth server when an Application is 
	 * created.  Please contact Admin or App owner to get the Secret key.
	 * 
	 * @param clientID
	 */
	public static void setClientSecret(String clientSecret) {
		JWTTokenFactory.clientSecret = clientSecret;
	}

	/**
	 * Set the location to the Public key used to decrypt the OAuth token.  The file
	 * should be obtained from the FoggyStreet OAuth server under the FOGGY_OAUTH_HOME/keys/authPublic.pkcs8
	 * 
	 * The file is a PKCS8 PEM file written out as a JSON object.  You are able to view the actual PEM
	 * from inside the OAuth Management GUI console.  
	 * 
	 * Note. the authPublic.pkcs8 file is a PEM file converted to a simple JSON object.
	 * 
	 * Note. If no FOGGY_OAUTH_HOME is set it uses current directory to locate the key.
	 * 
	 * @throws Exception
	 */
	public static void setPublicKeyPathUsingHomeEnv() throws Exception {
		String homePath = getHomePathEnv();

		if (homePath != null) {
			pathPublicKey = homePath + File.separator + KEYS_JOBS + File.separator + AUTH_PUBLIC_KEY_FILENAME;
		} else {
			pathPublicKey = AUTH_PUBLIC_KEY_FILENAME;
		}
	}

	/**
	 * Test if the JWT token is in the HTTP request header it does multiple 
	 * checks to make sure the capitalization is correct.  It performs the following 
	 * checks
	 * 
	 * 1. Authorization: bearer  {token}
	 * 2. Authorization: Bearer  {token}
	 * 3. Authorization: BEARER  {token}
	 * 
	 * Note. Authorization is allways starts with a capital A
	 * 
	 * @param request
	 * @return
	 */
	public static boolean containsBearerTokenInHeader(HttpServletRequest request) {
		String token = request.getHeader(AUTH_HEADER);

		if (token == null || token.trim().equals("")) {
			return false;
		}

		if (token.startsWith(AUTH_HEADER_BEARER)) {
			return true;
		}
		if (token.startsWith(AUTH_HEADER_BEARER_LOWER)) {
			return true;
		}
		if (token.startsWith(AUTH_HEADER_BEARER_UPPER)) {
			return true;
		}
		return false;
	}

	/**
	 * Return the JWT token from the HTTP request header it does multiple 
	 * checks to make sure the capitalization is correct.  It performs the following 
	 * checks
	 * 
	 * 1. Authorization: bearer  {token}
	 * 2. Authorization: Bearer  {token}
	 * 3. Authorization: BEARER  {token}
	 * 
	 * Note. Authorization is allways starts with a capital A
	 * 
	 * @param request
	 * @return
	 */
	public static String getBearerTokenFromHeader(HttpServletRequest request) {
		String token = request.getHeader(AUTH_HEADER);

		if (token == null || token.trim().equals("")) {
			return null;
		}
		token = token.trim();

		if (token.startsWith(AUTH_HEADER_BEARER)) {
			return token.replaceFirst(AUTH_HEADER_BEARER, "").trim();
		}
		if (token.startsWith(AUTH_HEADER_BEARER_LOWER)) {
			return token.replaceFirst(AUTH_HEADER_BEARER_LOWER, "").trim();
		}
		if (token.startsWith(AUTH_HEADER_BEARER_UPPER)) {
			return token.replaceFirst(AUTH_HEADER_BEARER_UPPER, "").trim();
		}

		return token;
	}

	/**
	* Validate the presented token using the Public key, perform a check on 
	* the expire date of the token is found 
	 * 
	 * @param request
	 * @return
	 */
	public static Claims validateTokenWithExpireCheck(String token) throws Exception {

		if (token == null || token.trim().equals("")) {
			return null;
		}

		TokenFactory factory = new TokenFactory(null, pathPublicKey);
		Claims claims = factory.validateTokenWithExpiry(token);
		if (claims == null) {
			return null;
		}
		return claims;

	}

	/**
	* Validate the presented token using the Public key, DO not perform a check on 
	* the expire date of the token.
	* 
	* It does a signature check using the Public key
	 * 
	 * @param request
	 * @return
	 */
	public static Claims validateTokenNoExpireCheck(String token) throws Exception {

		if (token == null || token.trim().equals("")) {
			return null;
		}

		TokenFactory factory = new TokenFactory(null, pathPublicKey);
		Claims claims = factory.validateToken(token);
		if (claims == null) {
			return null;
		}
		return claims;

	}
	
	/**
	 * Validate the presented token using the Public key, DO not perform a check on 
	 * the expire date of the token and check to see if the Audience field
	 * contains the applicationID
	 * 
	 * 1. It does a signature check using the Public key
	 * 2. Checks to locate the applicationID inside the Audience
	 * 
	 * @param request
	 * @return
	 */	
	public static Claims validateTokenIncludeApplicationID(String token) throws Exception {

		if (token == null || token.trim().equals("")) {
			return null;
		}

		TokenFactory factory = new TokenFactory(null, pathPublicKey);
		Claims claims = factory.validateTokenWithExpiry(token);
		if (claims == null) {
			return null;
		}
		
		if (oauthApplicationID != null) {
			DecodedJWT decode = JWT.decode(token);
			for (String anApp : decode.getAudience()) {
				if (oauthApplicationID.equalsIgnoreCase(anApp)) {
					return claims;
				}
			}
		}
		return null;

	}
	
	/**
	 * Test to see if the Audience field of the token contains the 
	 * applicationID.  The applicationID is set using the method.
	 * 
	 *          public static void setOauthApplicationID( appID ); 
	 * 
	 * Example:JWTTokenFactory.setOauthApplicationID(
	 * 
	 *    
	 * @param token
	 * @return
	 * @throws Exception
	 */
	public static boolean tokenContainsAppID(String token) throws Exception {

		if (token == null || token.trim().equals("")) {
			return false;
		}

		if (oauthApplicationID != null) {
			DecodedJWT decode = JWT.decode(token);
			for (String anApp : decode.getAudience()) {
				if (oauthApplicationID.equalsIgnoreCase(anApp)) {
					return true;
				}
			}
		}
		return false;

	}
	
	/**
	 * Test to see if the claim has expired, uses current time
	 * 
	 * @param claim
	 * @return
	 * @throws Exception
	 */
	public static boolean isTokenExpired(Claims claim) throws Exception {

		if (claim == null) {
			return true;
		}

		Date exp = new Date();
			
		Date expire = claim.getExpiration();
		if (expire != null) {
			if (expire.before(exp)) {
				return false;
			} else {
				return true;
			}
		} else {
			return false;
		}

	}
	
	/**
	 * Return the FOGGY_OAUTH_HOME value form the 
	 * system environment vairables.
	 * 
	 * Please see documents for how to set the Operating 
	 * system environment variables.
	 * 
	 * @return
	 * @throws Exception
	 */
	private static String getHomePathEnv() throws Exception {
		String homePath = (String) System.getenv(ApplicationConfig.FOGGY_OAUTH_HOME.toString());

		if (homePath == null) {
			return null;
		}

		File homeFile = new File(homePath);
		if (homeFile.exists()) {
			return homePath;
		}
		return null;
	}
	
	
	/**
	 * Perform the Auth request REST call to the OAuth server, 
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 * 
	 * This method does not set the state param value.
	 * 
	 * Calling this method will prompt the user to see the Login screen from the oAuth server
	 * 
	 * @param appName - The applicationID of the app, should match the AppID from Foggystreet Oauth server
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<String> oauth2AuthenticationRequest(String appName) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", "code");
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		ub.addParameter("scope", appName);
				
		return sendGet(ub.toString());
		
	}
	
	/**
	 * Perform the Auth request REST call to the OAuth server, 
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 * 
	 * This method does not set the state param value.
	 * 
	 * @param appName - The applicationID of the app, should match the AppID from Foggystreet Oauth server
	 * @state - A value to provide extra security for the client, to stop replay attacks.  The OAuth server
	 * will resend the state value back in the Redirect URL call.
	 * 
	 * Calling this method will prompt the user to see the Login screen from the oAuth server
	 * 
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oauth2AuthenticationRequest(String appName,String state) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", "code");
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		ub.addParameter("scope", appName);
		ub.addParameter("state", state);
				
		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		
	}
	
	/**
	 * Perform the Auth request REST call to the OAuth server,
	 *  
	 * This is a special method that should only be used from Browsers using the Async HttpRequest or Fetch 
	 * Javascript libraries. If you are getting CORS erros on the redirect you should use this method.
	 * 
	 * In order to stop the Browser from intercepting the 302 HTTP redirect call from
	 * the OAuth server, you have the ability to force the OAuth server to send the call back as HTTP 200 OK.
	 * 
	 * This will allow calls to be passed through to the Fetch javascript code to handle as necessary.
	 * The location header will be set with the URL of the login screen.
	 *  
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 * 
	 * 
	 * @param appName - The applicationID of the app, should match the AppID from Foggystreet Oauth server
	 * @state - A value to provide extra security for the client, to stop replay attacks.  The OAuth server
	 * will resend the state value back in the Redirect URL call.
	 * 
	 * Calling this method will prompt the user to see the Login screen from the oAuth server
	 * 
	 * httpResponse200 - Pass the value "true" to make the OAuth server return the response as 200 HTTP OK status
	 * instead of the 302 REDITECT.
	 *  
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oauth2AuthenticationRequest(String appName,String state,String httpResponse200) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", "code");
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		ub.addParameter("scope", appName);
		ub.addParameter("state", state);
		if (httpResponse200 != null && !httpResponse200.trim().equals("")) {
			ub.addParameter("httpResponse200", httpResponse200);
		}
		
		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		httpHeaders.add("Access-Control-Allow-Origin", "*");
		httpHeaders.add("Access-Control-Allow-Headers", "Location, Authorization");
		httpHeaders.add("Access-Control-Expose-Headers", "Location, Authorization");	
		httpHeaders.add("Access-Control-Allow-Credentials", "true");
		httpHeaders.add("Access-Control-Allow-Methods", "GET, OPTIONS");
		
		if (StringCheck.isNullOrEmpty(httpResponse200)) {
			return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		} else {
			return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		}
		
	}

	/**
	 * Perform the Auth request REST call to the OAuth server,
	 *  
	 * This is a special method that should only be used from Browsers using the Async HttpRequest or Fetch 
	 * Javascript libraries. If you are getting CORS erros on the redirect you should use this method.
	 * 
	 * In order to stop the Browser from intercepting the 302 HTTP redirect call from
	 * the OAuth server, you have the ability to force the OAuth server to send the call back as HTTP 200 OK.
	 * 
	 * This will allow calls to be passed through to the Fetch javascript code to handle as necessary.
	 * The location header will be set with the URL of the login screen.
	 *  
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 * 
	 * 
	 * @param appName - The applicationID of the app, should match the AppID from Foggystreet Oauth server
	 * @state - A value to provide extra security for the client, to stop replay attacks.  The OAuth server
	 * will resend the state value back in the Redirect URL call.
	 * 
	 * Calling this method will prompt the user to see the Login screen from the oAuth server
	 * 
	 * httpResponse200 - Pass the value "true" to make the OAuth server return the response as 200 HTTP OK status
	 * instead of the 302 REDITECT.
	 *  
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oauth2AuthenticationRequestHttpOK(String responseType,String appName,String state,String httpResponse200) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", responseType);
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		ub.addParameter("scope", appName);
		ub.addParameter("state", state);
		if (httpResponse200 != null && !httpResponse200.trim().equals("")) {
			ub.addParameter("httpResponse200", httpResponse200);
		}
		
		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		httpHeaders.add("Access-Control-Allow-Origin", "*");
		httpHeaders.add("Access-Control-Allow-Headers", "Location, Authorization");
		httpHeaders.add("Access-Control-Expose-Headers", "Location, Authorization");	
		httpHeaders.add("Access-Control-Allow-Credentials", "true");
		httpHeaders.add("Access-Control-Allow-Methods", "GET, OPTIONS");
		
		if (StringCheck.isNullOrEmpty(httpResponse200)) {
			return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		} else {
			return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		}
		
	}
	
	/**
	 * Perform the Auth request REST call to the OAuth server,
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/auth
	 	
	 	perform the call with extra security, use the codeChallenge and codeChallengeMethod
	 	parameters to provide extra security in the token request.
	 	
	 * @param appName - The applicationID of the app, should match the AppID from Foggystreet Oauth server
	 * @param state - A value to provide extra security for the client, to stop replay attacks.  The OAuth server
	 *                will resend the state value back in the Redirect URL call.
	 * @param codeChallenge - A plain or hased value of a random string used by the OAuth server to guarantee this client is 
	 *                        making the /token request call.
	 * @param codeChallengeMethod - the value indicating if the codeChallenge is plain or hashed (can be the values   plain or s256 )
	 *                            - The values can be found   
	 *                            
	 *                            JWTTokenFactory.CODE_CHALLENGE_METHOD_PLAIN
	 *                            JWTTokenFactory.CODE_CHALLENGE_METHOD_S256
	 *                            
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oauth2AuthenticationRequest(String appName,String state,String codeChallenge,String codeChallengeMethod) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", "code");
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		ub.addParameter("scope", appName);
		ub.addParameter("state", state);
		ub.addParameter("code_challenge", codeChallenge);
		ub.addParameter("code_challenge_method", codeChallengeMethod);
				
		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		
	}
	
	/**
	 * Perfrom the REST call to the /token OAuth endpoint.  A call to this method
	 * will return an JWT access token and refresh token.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/token
	 *  
	 *  This method performs a grant_type:authorization_code request
	 * 
	 * granttype:authorization_code 
	 * @param code - The code returned from the OAuth server to your callback redirect REST API.
	 * @return
	 * @throws Exception
	 */
	public static FoggyStreetOauthBO oauth2TokenRequestAuthCode(String code) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenURL);
		urlParameters.add(new BasicNameValuePair("client_id", clientID));
		urlParameters.add(new BasicNameValuePair("client_secret", clientSecret));
		urlParameters.add(new BasicNameValuePair("code", code));
		urlParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
		ub.addParameters(urlParameters);
		
		ResponseEntity<String> token = sendPost(ub.toString());
		if (token == null) {
			return null;
		}
		
		String json = token.getBody();	
		return (FoggyStreetOauthBO) mapper.readValue(json,FoggyStreetOauthBO.class);
		
	}

	/**
	 * Perfrom the REST call to the /token OAuth endpoint.  A call to this method
	 * will return an JWT access token and refresh token.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/token
	 *  
	 *  This method performs a grant_type:authorization_code request
	 * 
	 * granttype:authorization_code 
	 * @param code - The code returned from the OAuth server to your callback redirect REST API.
	 * @param code_verifier - Extra security field containing the plain text (non hashed) value of the codeChallenge
	 *                        value sent in the /auth REST API call.  The OAuth server will verify the request
	 *                        against the original values sent as codeChallenge and codeChallengeMethod.
	 *                        
	 *                        Note. this value is the actual value (non hashed value)
	 *                        
	 * @return
	 * @throws Exception
	 */
	public static FoggyStreetOauthBO oauth2TokenRequestAuthCode(String code,String code_verifier) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenURL);
		urlParameters.add(new BasicNameValuePair("client_id", clientID));
		urlParameters.add(new BasicNameValuePair("client_secret", clientSecret));
		urlParameters.add(new BasicNameValuePair("code", code));
		urlParameters.add(new BasicNameValuePair("code_verifier", code_verifier));
		urlParameters.add(new BasicNameValuePair("grant_type", "authorization_code"));
		ub.addParameters(urlParameters);
		
		ResponseEntity<String> token = sendPost(ub.toString());
		if (token == null) {
			return null;
		}
		
		String json = token.getBody();	
		return (FoggyStreetOauthBO) mapper.readValue(json,FoggyStreetOauthBO.class);
		
	}
	
	/**
	 * Request a call to the /token REST endpoint.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/token
	 * 
	 * This method will perform multiple functions depending on whether the client sends in
	 * 1) An accessToken without a refreshToken
	 * 2) Both accessToken and refreshToken
	 * 3) A expired accessToken and a refreshToken
	 * 4) An accessToken with a missing Audience value.
	 *  
	 * The call will try to either
	 * 
	 *  1) Create a new accessToken with updated Audience field (based on the clientID)
	 *  2) Create a new accessToken replacing the expired token
	 *  3) Return the same accessToken if it already contains the Audience field and is not expired.
	 *  
	 *  This method performs a grant_type: refresh_token request
	 *  
	 *  Use this call 
	 * @param refreshToken - An optional value, it must be presented if the accessToken is expired. 
	 * @param accessToken - Mandatory value, you must always present an accessToken (Note. it can be expired) 
	 * @return
	 * @throws Exception
	 */
	public static FoggyStreetOauthBO oauth2TokenRequestRefreshToken(String refreshToken,String accessToken) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenURL);
		urlParameters.add(new BasicNameValuePair("client_id", clientID));
		urlParameters.add(new BasicNameValuePair("client_secret", clientSecret));
		urlParameters.add(new BasicNameValuePair("grant_type", "refresh_token"));
		if (refreshToken != null) {
			urlParameters.add(new BasicNameValuePair("refresh_token", refreshToken));
		}
		if (accessToken != null) {
			urlParameters.add(new BasicNameValuePair("access_token", accessToken));
		}
		
		ub.addParameters(urlParameters);
		
		ResponseEntity<String> token = sendPost(ub.toString());
		if (token == null) {
			return null;
		}
		
		String json = token.getBody();	
		return (FoggyStreetOauthBO) mapper.readValue(json,FoggyStreetOauthBO.class);
		
	}
	
	/**
	 * Request a call to the /token REST endpoint.
	 * 
	 * Note. this method must have a non expired accessToken provided.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/token
	 * 
	 * This method will perform multiple functions depending on whether the client sends in
	 * 1) An accessToken without a refreshToken
	 * 2) An accessToken with a missing Audience value.
	 *  
	 * The call will try to either
	 * 
	 *  1) Create a new accessToken with updated Audience field (based on the clientID)
	 *  2) Return the same accessToken if it already contains the Audience field and is not expired.
	 *  
	 *  This method performs a grant_type: refresh_token request
	 *  
	 * @param accessToken - Mandatory value, you must always present an accessToken (Note. it can NOT be expired) 
	 * @return
	 * @throws Exception
	 */
	public static FoggyStreetOauthBO oauth2TokenRequestRefreshToken(String accessToken) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenURL);
		urlParameters.add(new BasicNameValuePair("client_id", clientID));
		urlParameters.add(new BasicNameValuePair("client_secret", clientSecret));
		urlParameters.add(new BasicNameValuePair("grant_type", "refresh_token"));
		if (accessToken != null) {
			urlParameters.add(new BasicNameValuePair("access_token", accessToken));
		}
		
		ub.addParameters(urlParameters);
		
		ResponseEntity<String> token = sendPost(ub.toString());
		if (token == null) {
			return null;
		}
		
		String json = token.getBody();	
		return (FoggyStreetOauthBO) mapper.readValue(json,FoggyStreetOauthBO.class);
		
	}
	
	/**
	 * Return information about the RefreshToken.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/tokeninfo?refresh_token=...
	 *  
	 *  This will check the oAuth database to check if its been revoked or expired.
	 *  
	 * @param refreshToken
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<String> oauth2TokenInfoRequestRefreshToken(String refreshToken) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenInfoURL);
		if (refreshToken != null) {
			urlParameters.add(new BasicNameValuePair("refresh_token", refreshToken));
		}

		ub.addParameters(urlParameters);
		
		return sendGet(ub.toString());
		
	}

	/**
	 * Return information about the AccessToken.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/tokeninfo?access_token=...
	 *  
	 *  This will check the oAuth database to check if its been revoked or expired.
	 *  
	 * @param accessToken
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<String> oauth2TokenInfoRequestAccessToken(String accessToken) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthTokenInfoURL);
		if (accessToken != null) {
			urlParameters.add(new BasicNameValuePair("access_token", accessToken));
		}
		
		ub.addParameters(urlParameters);
		
		return sendGet(ub.toString());
		
	}
	
	/**
	 * Return user information about the owner of the access token.
	 * 
	 *  http://Server:Port/foggystreetauth/rest/oauth2/v1/userinfo?access_token=...
	 *  
	 * @param accessToken
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<String> oauth2UserInfoRequestAccessToken(String accessToken) throws Exception {
		List<NameValuePair> urlParameters = new ArrayList<NameValuePair>();
		URIBuilder ub = new URIBuilder(oauthUserInfoURL);
		if (accessToken != null) {
			urlParameters.add(new BasicNameValuePair("access_token", accessToken));
		}
		
		ub.addParameters(urlParameters);
		
		return sendGet(ub.toString());
		
	}
	
	
	/**
	 *  Perform the Auth request REST call to the OAuth server,
	 *  
	 * @param oidcResponseType - String of response_type, please use the builder methods from OIDCResponseTypes enum 
	 * 
	 * 				Example: OIDCResponseTypes.getIDTokenToken() .... 
	 * @param openIDScope - Can be Null or OIDCScopeTypes.openid, if openid added then openid will be added to scope
	 * @param appName - The application name, if empty/null uses the value JWTTokenFactory.oauthApplicationID set at initialise
	 * @param state - A state value if required
	 * @param nonce - A nonce value if required
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oidcAuthenticationRequest(String oidcResponseType,OIDCScopeTypes openIDScope,String appName,String state, String nonce) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", oidcResponseType);
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		if (StringCheck.isNullOrEmpty(appName)) {
			appName = oauthApplicationID;
		}
		if (openIDScope != null) {
			ub.addParameter("scope", OIDCScopeTypes.insertOpenID(appName) );
		} else {
			ub.addParameter("scope", appName);
		}
		
		if (!StringCheck.isNullOrEmpty(state)) {
			ub.addParameter("state", state);
		}
		if (!StringCheck.isNullOrEmpty(nonce)) {
			ub.addParameter("nonce", nonce);
		}
		
		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		httpHeaders.add("Access-Control-Allow-Origin", "*");
		httpHeaders.add("Access-Control-Allow-Headers", "Location, Authorization");
		httpHeaders.add("Access-Control-Expose-Headers", "Location, Authorization");	
		httpHeaders.add("Access-Control-Allow-Credentials", "true");
		httpHeaders.add("Access-Control-Allow-Methods", "GET, OPTIONS");
		
		return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		
	}

	/**
	 *  Perform the Auth request REST call to the OAuth server,
	 *  
	 * @param oidcResponseType - String of response_type, please use the builder methods from OIDCResponseTypes enum 
	 * 
	 * 				Example: OIDCResponseTypes.getIDTokenToken() .... 
	 * 
	 * @param openIDScope - Can be Null or OIDCScopeTypes.openid, if openid added then openid will be prepended to appName to form the scope
	 * @param appName - The application name, if empty/null uses the value JWTTokenFactory.oauthApplicationID set at initialize
	 * @param state - A state value if required, can be null
	 * @param nonce - A nonce value if required, can be null
	 * @param code_challenge - A code_challenge value if required, can be null
	 * @param code_challenge_method - A code_challenge_method value if required  (can be the values   plain or s256 )
	 *                            - The values can be found   
	 *                            
	 *                            JWTTokenFactory.CODE_CHALLENGE_METHOD_PLAIN
	 *                            JWTTokenFactory.CODE_CHALLENGE_METHOD_S256
	 * @return
	 * @throws Exception
	 */
	public static ResponseEntity<Object> oidcAuthenticationRequest(String oidcResponseType,OIDCScopeTypes openIDScope,String appName,String state, String nonce,String codeChallenge,String codeChallengeMethod) throws Exception {
		URIBuilder ub = new URIBuilder(oauthAuthenticationURL);
		ub.addParameter("response_type", oidcResponseType);
		ub.addParameter("client_id", clientID);
		ub.addParameter("redirect_uri", redirectURL);
		if (StringCheck.isNullOrEmpty(appName)) {
			appName = oauthApplicationID;
		}
		if (openIDScope != null) {
			ub.addParameter("scope", OIDCScopeTypes.insertOpenID(appName) );
		} else {
			ub.addParameter("scope", appName);
		}
		
		if (!StringCheck.isNullOrEmpty(state)) {
			ub.addParameter("state", state);
		}
		if (!StringCheck.isNullOrEmpty(nonce)) {
			ub.addParameter("nonce", nonce);
		}
		if (!StringCheck.isNullOrEmpty(codeChallenge)) {
			ub.addParameter("code_challenge", codeChallenge);
		}
		if (!StringCheck.isNullOrEmpty(codeChallengeMethod)) {
			ub.addParameter("code_challenge_method", codeChallengeMethod);
		}

		URI uri = new URI(ub.toString());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.setLocation(uri);
		httpHeaders.add("Access-Control-Allow-Origin", "*");
		httpHeaders.add("Access-Control-Allow-Headers", "Location, Authorization");
		httpHeaders.add("Access-Control-Expose-Headers", "Location, Authorization");	
		httpHeaders.add("Access-Control-Allow-Credentials", "true");
		httpHeaders.add("Access-Control-Allow-Methods", "GET, OPTIONS");
		
		return new ResponseEntity<>(httpHeaders, HttpStatus.SEE_OTHER);
		
	}

	
	private static ResponseEntity<String> sendGet(String uri) throws Exception {

		RestTemplate restTemplate = null;
		if (uri.startsWith("https")) {
			TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
				@Override
				public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
					return true;
				}
			};
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());

			CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(httpClient);
			restTemplate = new RestTemplate(requestFactory);
		} else {
			restTemplate = new RestTemplate();
		}

		URI uriObj = new URI(uri.toString());
		HttpHeaders headers = new HttpHeaders();
		headers.setLocation(uriObj);		
		HttpEntity<String> entity = new HttpEntity<String>(headers);
		
		return restTemplate.exchange(uri, HttpMethod.GET, entity, String.class);

	}
	
	
	private static ResponseEntity<String> sendPost(String uri) throws Exception {

		RestTemplate restTemplate = null;
		if (uri.startsWith("https")) {
			TrustStrategy acceptingTrustStrategy = new TrustStrategy() {
				@Override
				public boolean isTrusted(X509Certificate[] x509Certificates, String s) throws CertificateException {
					return true;
				}
			};
			SSLContext sslContext = org.apache.http.ssl.SSLContexts.custom().loadTrustMaterial(null, acceptingTrustStrategy).build();
			SSLConnectionSocketFactory csf = new SSLConnectionSocketFactory(sslContext, new NoopHostnameVerifier());

			CloseableHttpClient httpClient = HttpClients.custom().setSSLSocketFactory(csf).build();
			HttpComponentsClientHttpRequestFactory requestFactory = new HttpComponentsClientHttpRequestFactory();
			requestFactory.setHttpClient(httpClient);
			restTemplate = new RestTemplate(requestFactory);
		} else {
			restTemplate = new RestTemplate();
		}

		HttpHeaders headers = new HttpHeaders();
		headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

		HttpEntity<String> entity = new HttpEntity<String>(headers);
		return restTemplate.exchange(uri, HttpMethod.POST, entity, String.class);

	}
	
	
	public static String createS256CodeChallenge(String codeChallenge) throws Exception {
		MessageDigest shaDigest = MessageDigest.getInstance("SHA-256");
		shaDigest.update(codeChallenge.getBytes());
		byte[] digest = shaDigest.digest();

		codeChallenge = Base64.getEncoder().encodeToString(digest);

		// replace all not allowed characters
		codeChallenge = codeChallenge.replace('/', '-');
		codeChallenge = codeChallenge.replace('+', '_');
		codeChallenge = codeChallenge.replaceAll("=", "");

		int size = codeChallenge.length();
		if (size < CODE_CHALLENGE_MIN_LENGTH) {
			size = CODE_CHALLENGE_MIN_LENGTH;
		}
		if (size > CODE_CHALLENGE_MAX_LENGTH) {
			size = CODE_CHALLENGE_MAX_LENGTH;
		}
		char[] codeValue = new char[size];
		for (int i = 0; i < size; i++) {
			codeValue[i] = codeChallenge.charAt(i);
		}
		return new String(codeValue);

	}
}
