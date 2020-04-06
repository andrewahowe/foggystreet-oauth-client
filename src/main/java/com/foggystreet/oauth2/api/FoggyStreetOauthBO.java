package com.foggystreet.oauth2.api;

import java.util.ArrayList;
import java.util.List;

import com.howe.gui.bo.AbsRestObject;

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

	JSON object class returned from the OAuth server containing the latest tokens and Roles
	
	Note. There is a Boolean field called replaceRolesFlag, if it is set to true.
	the client should replace all the current user roles with the supplied values
	in the roles variable.
	
	it is a full replace ALL of all roles, if ALL the roles are to be removed then an empty
	List should be returned.
	
	
 **/
public class FoggyStreetOauthBO extends AbsRestObject {

	private String token;
	private String idToken;
	private String refreshToken;
	private List<String> roles = new ArrayList();
	private boolean replaceRolesFlag = false;
	
	/**
	 * The acess token returned from OAuth server
	 * @return
	 */
	public String getToken() {
		return token;
	}
	public void setToken(String token) {
		this.token = token;
	}
	
	/**
	 * The User ROLES returned.
	 * 
	 * please see the flag isReplaceRolesFlag() that is used
	 * to indicate if the Roles returned are to replace the current
	 * roles.
	 * 
	 * @return
	 */
	public List<String> getRoles() {
		return roles;
	}
	public void setRoles(List<String> roles) {
		this.roles = roles;
	}
	
	/**
	 * A flag indicating that the Roles returned 
	 * should overwrite all the current roles.
	 * 
	 * If true then all current roles should be removed
	 * and replaced with the roles returned.
	 * 
	 * @return
	 */
	public boolean isReplaceRolesFlag() {
		return replaceRolesFlag;
	}
	public void setReplaceRolesFlag(boolean replaceRolesFlag) {
		this.replaceRolesFlag = replaceRolesFlag;
	}
	
	/**
	 * The refresh token returned from the oAuth server
	 * 
	 * Can be null if no refresh token is used for the application.
	 * 
	 * @return
	 */
	public String getRefreshToken() {
		return refreshToken;
	}
	public void setRefreshToken(String refreshToken) {
		this.refreshToken = refreshToken;
	}
	public String getIdToken() {
		return idToken;
	}
	public void setIdToken(String idToken) {
		this.idToken = idToken;
	}
	
	
}
