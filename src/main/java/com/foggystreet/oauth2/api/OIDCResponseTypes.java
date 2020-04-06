package com.foggystreet.oauth2.api;

public enum OIDCResponseTypes {

	code,
	id_token,
	token;
	
	/**
	 * The OICD code response type
	 * 1) when no openid in scope, only Access token returned from /token flow
	 * 2) when openid is in scope, ID token will be returned from /token flow
	 * @return
	 */
	public static String getCode() {
		return code.toString();
	}
	
	/**
	 * The OICD id_token response type
	 * 1) ID token returned from /auth flow only
	 * 2) no tokens from /token
	 * 
	 * This is an implicit flow and is good to get around CORS issues or directly from 
	 * a web page.  All calls allways go back to the same hostname, even on the login page
	 * so there are no CORS issues.
	 * @return
	 */
	public static String getIDToken() {
		return id_token.toString();
	}
	
	/**
	 * The OICD token response type
	 * 1) Access token returned from /auth flow only
	 * 2) no tokens from /token
	 * 
	 * This is an implicit flow and is good to get around CORS issues or directly from 
	 * a web page.  All calls allways go back to the same hostname, even on the login page
	 * so there are no CORS issues.
	 * @return
	 */
	public static String getToken() {
		return token.toString();
	}
	
	/**
	 * The OICD id_token token response type
	 * 1) ID token returned from /auth flow
	 * 2) Access token returned from /auth flow
	 * 3) no tokens from /token
	 * 
	 * This is an implicit flow and is good to get around CORS issues or directly from 
	 * a web page.  All calls allways go back to the same hostname, even on the login page
	 * so there are no CORS issues.
	 * @return
	 */
	public static String getIDTokenToken() {
		return id_token.toString() + " " + token.toString();
	}
	
	/**
	 * The OICD code id_token response type
	 * 1) ID token returned from /auth flow
	 * 2) ID token returned from /token flow
	 * 3) Access token returned from /token flow
	 * 
	 * @return
	 */
	public static String getCodeIDToken() {
		return code.toString() + " " + id_token.toString();
	}

	/**
	 * The OICD code id_token response type
	 * 1) Access token returned from /auth flow only
	 * 2) with openid in scope, ID token returned from /token flow
	 * 3) with no openid in scope, no ID token returned from /token flow
	 * 4) Access token returned from /token flow
	 * 
	 * @return
	 */
	public static String getCodeToken() {
		return code.toString() + " " + token.toString();
	}
	
	/**
	 * The OICD code id_token token response type
	 * 1) Access token returned from /auth flow
	 * 2) ID token returned from /auth flow
	 * 3) ID token returned from /token flow
	 * 4) Access token returned from /token flow
	 * 
	 * @return
	 */
	public static String getCodeIDTokenToken() {
		return code.toString() + " " + id_token.toString() + " " + token.toString();
	}
	
}
