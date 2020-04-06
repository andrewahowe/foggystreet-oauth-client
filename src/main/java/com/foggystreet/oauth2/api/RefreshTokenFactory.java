package com.foggystreet.oauth2.api;

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

	Interface used by RestSecurity class to obtain the refreshToken for the 
	presented Claim.  The user should create a class to perform the necessary
	functions to return the token.
	 
	
 **/
public interface RefreshTokenFactory {

	/**
	 * Method to return the RefreshToken for the current claim.
	 * The unique ID is obtained from the claim using claim.getId()
	 * 
	 * The user will need to perform all the necassry DB calls etc.
	 * 
	 * @param claim
	 * @return
	 */
	public String getRefreshToken(Claims claim);
	
}
