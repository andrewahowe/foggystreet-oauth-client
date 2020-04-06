package com.foggystreet.oauth2.api;

import java.util.UUID;

import org.springframework.http.HttpStatus;

import com.howe.gui.bo.AbsServerResponse;

/**
* @Copyright 2019 Andrew Howe 
* All rights reserved, this software may not be reproduced 
* or distributed in whole or in part in any manner without 
* the permission of the copyright owner.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
* 
* Helper class used by the client to perform REST security checks,
* Used internally inside the RestSecurity class.
* 
* 
**/

public class AppHttpStatusResponse {

	private int statusCode;
	private String errorMessage;
	private AbsServerResponse httpReplyBO;
	private String requestCorrelationID;
	private FoggyStreetOauthBO reply;
	
	public AppHttpStatusResponse() {
		// correlation ID used for logging
		 requestCorrelationID = UUID.randomUUID().toString();
	}
	
	/**
	 * Answer if the HTTP status is UNAUTHORIZED 401
	 * @return
	 */
	public boolean isUnauthorized() {
		return this.statusCode == HttpStatus.UNAUTHORIZED.value();
	}
	
	/**
	 * Answer if the HTTP status is OK 200
	 * @return
	 */
	public boolean isOK() {
		return this.statusCode == HttpStatus.OK.value();
	}
	
	/**
	 * A error message will be set by the RestSecurity class if an error occurs
	 * @return
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	public void setErrorMessage(String errorMessage) {
		this.errorMessage = errorMessage;
	}

	/**
	 * Get the returned status code if a REST call is made.
	 * @return
	 */
	public int getStatusCode() {
		return statusCode;
	}

	public void setStatusCode(int statusCode) {
		this.statusCode = statusCode;
	}

	/**
	 * Get the raw HTTP reply from the REST call
	 * @return
	 */
	public AbsServerResponse getHttpReplyBO() {
		return httpReplyBO;
	}

	public void setHttpReplyBO(AbsServerResponse httpReplyBO) {
		this.httpReplyBO = httpReplyBO;
	}

	/**
	 * A unique ID for the rest call if you need to 
	 * correlate multiple calls together.
	 * 
	 * This is currently on used as only 1 REST call is made withing 
	 * the RestSecurity class.
	 * 
	 * @return
	 */
	public String getRequestCorrelationID() {
		return requestCorrelationID;
	}

	public void setRequestCorrelationID(String requestCorrelationID) {
		this.requestCorrelationID = requestCorrelationID;
	}

	/**
	 * return the new Access tokens and refresh tokens and Roles.
	 * @return
	 */
	public FoggyStreetOauthBO getReply() {
		return reply;
	}

	public void setReply(FoggyStreetOauthBO reply) {
		this.reply = reply;
	}
	
	
}
