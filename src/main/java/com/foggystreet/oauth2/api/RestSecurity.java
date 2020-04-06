package com.foggystreet.oauth2.api;

import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.http.HttpStatus;

import com.howe.gui.bo.AbsServerResponse;
import com.howe.helper.StringCheck;

import io.jsonwebtoken.Claims;

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

	Helper class the should be used by the Application to perform the JWT token
	validation inside each REST function.
	
	The class contains all the functions to perform TOken validation using Public key.
	
	Before using this class you must make sure the JWTTokenFactory variables have been set as 
	this class uses them to find the Public Key location and also the REST URLs to the OAuth server endpoints.
	
	See:  The following should have been set in the application at startup.
	
	 JWTTokenFactory.setOauthApplicationID(..);
	 JWTTokenFactory.setOauthAuthenticationURL(..);
	 JWTTokenFactory.setOauthTokenURL(..);
	 JWTTokenFactory.setOauthTokenInfoURL(..);
	 JWTTokenFactory.setPublicKeyPath(..); 
	 JWTTokenFactory.setClientID(..);
	 JWTTokenFactory.setClientSecret(..); 
	 JWTTokenFactory.setRedirectURL(..);
	  
	
	Example:
	
	@CrossOrigin
	@RequestMapping(value = "/v1/test", method = RequestMethod.POST, consumes = { MediaType.ALL_VALUE }, produces = { MediaType.APPLICATION_JSON_VALUE })
	public ResponseEntity<Object> testRESTCall(HttpServletRequest request, HttpServletResponse response, ......) {
	
		AppHttpStatusResponse appResponse = new AppHttpStatusResponse(); 	

		// user defined refresh token lookup class
		RefreshTokenFactory refreshLookup = new TestRefreshTokenFactory();

		Claims claims = RestSecurity.checkSecurityToken(request,response, appResponse, refreshLookup); 
		if (appResponse.isUnauthorized()) { 
			return new ResponseEntity<Object>(appResponse.getHttpReplyBO(), HttpStatus.UNAUTHORIZED); 
		}
		
		FoggyStreetOauthBO reply = appResponse.getReply();
		String accessToken = reply.getToken();
		String refreshToken = reply.getRefreshToken();
		
		if (reply.isReplaceRolesFlag()) {
			List<String> roles = reply.getRoles();
			
			// user to update the roles into DB
		}
		......
		.....
		....
		
		
	}
	
 **/

public abstract class RestSecurity {

	/**
	 * Return the timezone from the JWT claim
	 * @param aClaim
	 * @return
	 */
	public static String getTimezone(Claims aClaim) {
		String timezone = (String) aClaim.get("timezone");
		if (StringCheck.isNullOrEmpty(timezone)) {
			return "GMT";
		}
		return timezone;
	}

	/**
	 * Return the roles from the JWT claim
	 * @param aClaim
	 * @return
	 */
	public static String getRoles(Claims aClaim) {
		if (aClaim == null) {
			return null;
		}

		return (String) aClaim.get("roles");
	}

	/**
	 * Method provides the necessary function to protect a REST end point. For the
	 * supplied token the function will
	 * 
	 * 1) Valid the token against the PKCS8 public certificate 
	 * 2) Check the expiry date on token 
	 * 3) Check to see if the token contains the Audience scope defined 
	 * 4) Perform the necessary calls to the Ouath2 server to either 
	 * 		a) Refresh an expired access token 
	 *      b) request a new access token with the updated Audiences (add the current application ID to the Audience claims)
	 * 5) If a new access token is created store it on the HttpResponse in the Authorization header field
	 *        Authorization : bearer {new access token}
	 *        
	 * Before this method is called the JWTTokenFactory class should have all the
	 * set methods populated. i.e. This method required that the following have
	 * already been set
	 * 
	 * JWTTokenFactory.setOauthApplicationID(..);
	 * JWTTokenFactory.setOauthAuthenticationURL(..);
	 * JWTTokenFactory.setOauthTokenURL(..);
	 * JWTTokenFactory.setOauthTokenInfoURL(..);
	 * JWTTokenFactory.setPublicKeyPath(..); JWTTokenFactory.setClientID(..);
	 * JWTTokenFactory.setClientSecret(..); JWTTokenFactory.setRedirectURL(..);
	 * 
	 * An example of using this method
	 * 
	 * 
	 * RefreshTokenFactory refreshTokenLookup = null; // A class created by user to perform the refresh_token lookup for the user. 
	 * AppHttpStatusResponse appResponse = new AppHttpStatusResponse(); 
	 * Claims claims = RestSecurity.checkSecurityToken(request, response, appResponse,refreshTokenLookup); 
	 * if (appResponse.isUnauthorized()) { 
	 *    return new ResponseEntity<AbsRestObject>(appResponse.getHttpReplyBO(), HttpStatus.UNAUTHORIZED); 
	 * }
	 * 
	 * 
	 * @param request - HttpServletRequest
	 * @param response - HttpServletResponse
	 * @param appResponse
	 * @param refreshTokenLookup
	 *            - User defined class that will perform the Refresh token for the
	 *            user. If refresh tokens are not needed then enter null.
	 * @return Claims - A JWT claim object
	 * @throws Exception
	 */
	public static Claims checkSecurityToken(HttpServletRequest request, HttpServletResponse response, AppHttpStatusResponse appResponse, RefreshTokenFactory refreshTokenLookup) throws Exception {

		String token = JWTTokenFactory.getBearerTokenFromHeader(request);
		if (token == null || token.trim().equals("")) {
			AbsServerResponse responseObj = new AbsServerResponse();
			responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
			responseObj.setMessage("Please login");
			responseObj.setDeveloperMessage("No authorization token provided");

			appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
			appResponse.setHttpReplyBO(responseObj);

			return null;
		}

		Claims claims = JWTTokenFactory.validateTokenNoExpireCheck(token);
		if (claims == null) {
			AbsServerResponse responseObj = new AbsServerResponse();
			responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
			responseObj.setMessage("Please login");
			responseObj.setDeveloperMessage("Invalid authorization token provided");

			appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
			appResponse.setHttpReplyBO(responseObj);

			return null;
		}

		if (JWTTokenFactory.tokenContainsAppID(token)) {

			if (JWTTokenFactory.isTokenExpired(claims)) {
				// The token is Valid and it contains the Application ID already
				// but it is expired. So lets do a refresh token request
				// from the Auth server, pass in the opitional refresh_token if needed.
				// the user app will need to supply the class to get the token either
				// from memory or DB
				String refreshToken = null;
				if (refreshTokenLookup != null) {
					refreshToken = refreshTokenLookup.getRefreshToken(claims);
				}
				FoggyStreetOauthBO reply = JWTTokenFactory.oauth2TokenRequestRefreshToken(refreshToken, token);
				if (reply == null) {
					AbsServerResponse responseObj = new AbsServerResponse();
					responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
					responseObj.setMessage("Please login");
					responseObj.setDeveloperMessage("Invalid authorization token provided");

					appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
					appResponse.setHttpReplyBO(responseObj);

					return null;
				} else {
					// set the new reply containing the roles, the new tokens
					appResponse.setReply(reply);
					
					if (reply.getToken() != null && !reply.getToken().trim().equals("")) {
						response.setHeader(JWTTokenFactory.AUTH_HEADER, JWTTokenFactory.AUTH_HEADER_BEARER_LOWER + " " + reply.getToken());
					}
				}
			}

		} else {
			// request a new token from auth server to get the new Token with the updated
			// scope
			FoggyStreetOauthBO reply = JWTTokenFactory.oauth2TokenRequestRefreshToken(token);
			if (reply == null) {
				AbsServerResponse responseObj = new AbsServerResponse();
				responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
				responseObj.setMessage("Please login");
				responseObj.setDeveloperMessage("Invalid authorization token provided");

				appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
				appResponse.setHttpReplyBO(responseObj);

				return null;
			} else {
				// set the new reply containing the roles and the new tokens
				appResponse.setReply(reply);
				
				if (reply.getToken() != null && !reply.getToken().trim().equals("")) {
					response.setHeader(JWTTokenFactory.AUTH_HEADER, JWTTokenFactory.AUTH_HEADER_BEARER_LOWER + " " + reply.getToken());
				}
				
			}
		}

		return claims;
	}

	/**
	 * Method provides the necessary function to protect a REST end point. For the
	 * supplied token the function will
	 * 
	 * 1) Valid the token against the PKCS8 public certificate 2) Check the expiry
	 * date on token 3) Check to see if the token contains the Audience scope
	 * defined 4) Perform the necessary calls to the Ouath2 server to either a)
	 * Refresh an expired access token b) request a new access token with the
	 * updated Audiences (add the current application ID to the Audience claims)
	 * 
	 * Before this method is called the JWTTokenFactory class should have all the
	 * set methods populated. i.e. This method required that the following have
	 * already been set
	 * 
	 * JWTTokenFactory.setOauthApplicationID(..);
	 * JWTTokenFactory.setOauthAuthenticationURL(..);
	 * JWTTokenFactory.setOauthTokenURL(..);
	 * JWTTokenFactory.setOauthTokenInfoURL(..);
	 * JWTTokenFactory.setPublicKeyPath(..); JWTTokenFactory.setClientID(..);
	 * JWTTokenFactory.setClientSecret(..); JWTTokenFactory.setRedirectURL(..);
	 * 
	 * An example of using this method, if the token is stored on URL parameter and not the header
	 * use this method.
	 * 
	 * 
	 * RefreshTokenFactory refreshTokenLookup = null; // A class created by user to perform the refresh_token lookup for the user. 
	 * AppHttpStatusResponse appResponse = new AppHttpStatusResponse(); 
	 * Claims claims = RestSecurity.checkSecurityToken(token, appResponse,refreshTokenLookup); 
	 * if (appResponse.isUnauthorized()) { 
	 *    return new ResponseEntity<AbsRestObject>(appResponse.getHttpReplyBO(), HttpStatus.UNAUTHORIZED); 
	 * } else {
	 *    FoggyStreetOauthBO reply = appResponse.getReply();
		  if (reply.getToken() != null && !reply.getToken().trim().equals("")) {
			  httpResponse.setHeader(JWTTokenFactory.AUTH_HEADER, JWTTokenFactory.AUTH_HEADER_BEARER_LOWER + " " + reply.getToken());
		  }
	 * }
	 * 
	 * Note. The user will need to manually add the new JWT access token onto the response header.
	 * 
	 * @param token - The access token that is obtained previously.
	 * @param appResponse
	 * @param refreshTokenLookup
	 *            - User defined class that will perform the Refresh token for the
	 *            user. If refresh tokens are not needed then enter null.
	 * @return Claims - A JWT claim object
	 * @throws Exception
	 */
	public static Claims checkSecurityToken(String token, AppHttpStatusResponse appResponse, RefreshTokenFactory refreshTokenLookup) throws Exception {

		if (token == null || token.trim().equals("")) {
			AbsServerResponse responseObj = new AbsServerResponse();
			responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
			responseObj.setMessage("Please login");
			responseObj.setDeveloperMessage("No authorization token provided");

			appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
			appResponse.setHttpReplyBO(responseObj);

			return null;
		}

		Claims claims = JWTTokenFactory.validateTokenNoExpireCheck(token);
		if (claims == null) {
			AbsServerResponse responseObj = new AbsServerResponse();
			responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
			responseObj.setMessage("Please login");
			responseObj.setDeveloperMessage("No authorization token provided");

			appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
			appResponse.setHttpReplyBO(responseObj);

			return null;
		}

		if (JWTTokenFactory.tokenContainsAppID(token)) {

			if (JWTTokenFactory.isTokenExpired(claims)) {
				// The token is Valid and it contains the Application ID already
				// but it is expired. So lets do a refresh token request
				// from the Auth server, pass in the opitional refresh_token if needed.
				// the user app will need to supply the class to get the token either
				// from memory or DB
				String refreshToken = null;
				if (refreshTokenLookup != null) {
					refreshToken = refreshTokenLookup.getRefreshToken(claims);
				}
				FoggyStreetOauthBO reply = JWTTokenFactory.oauth2TokenRequestRefreshToken(refreshToken, token);
				if (reply == null) {
					AbsServerResponse responseObj = new AbsServerResponse();
					responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
					responseObj.setMessage("Please login");
					responseObj.setDeveloperMessage("Invalid authorization token provided");

					appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
					appResponse.setHttpReplyBO(responseObj);

					return null;
				} else {
					// set the new reply containing the roles, the new tokens
					appResponse.setReply(reply);
				}
			}

		} else {
			// request a new token from auth server to get the new Token with the updated
			// scope
			FoggyStreetOauthBO reply = JWTTokenFactory.oauth2TokenRequestRefreshToken(token);
			if (reply == null) {
				AbsServerResponse responseObj = new AbsServerResponse();
				responseObj.setStatus(HttpStatus.UNAUTHORIZED.value());
				responseObj.setMessage("Please login");
				responseObj.setDeveloperMessage("Invalid authorization token provided");

				appResponse.setStatusCode(HttpStatus.UNAUTHORIZED.value());
				appResponse.setHttpReplyBO(responseObj);

				return null;
			} else {
				// set the new reply containing the roles and the new tokens
				appResponse.setReply(reply);
				
			}
			
		}

		return claims;
	}

}
