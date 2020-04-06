package com.foggystreet.oauth2.api;

public enum OIDCScopeTypes {

	openid;
	
	public static String insertOpenID(String scope) {
		if (scope == null) {
			return openid.toString();
		}
		
		scope = scope.trim();
		return openid.toString() + " " + scope;
	}
}
