package org.keycloak.waffle.authenticator;

import javax.servlet.http.HttpServletRequest;

import org.keycloak.authentication.AuthenticationFlowContext;

import waffle.util.AuthorizationHeader;

/**
 * wrapper class for emulating the HttpServletRequest behavior 
 * @author bogdan
 *
 */
public class CustomAuthorizationHeader extends AuthorizationHeader {
	
	private static final String PUT = "PUT";
	private static final String POST = "POST";
	private static final String AUTHORIZATION = "Authorization";
	private AuthenticationFlowContext context;

	public CustomAuthorizationHeader(HttpServletRequest httpServletRequest) {
		super(httpServletRequest);
	}

	public CustomAuthorizationHeader(AuthenticationFlowContext context) {
		super(null);
		this.context = context;
	}
	
	public boolean isNtlmType1PostAuthorizationHeader() {
		String method = this.context.getHttpRequest().getHttpMethod();
		//here, the length is not obvious
		int length = this.context.getHttpRequest().getHttpHeaders().getLength();
		if (!POST.equals(method) && !PUT.equals(method)) {
			return false;
		}

		if (length != 0) {
			return false;
		}

		return this.isNtlmType1Message() || this.isSPNegTokenInitMessage();
	}
	
	@Override
	public String getHeader() {
		return this.context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst(AUTHORIZATION);
    }

}
