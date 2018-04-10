/**
 * @author bogdan
 */

package org.keycloak.waffle.authenticator;

import java.io.IOException;
import java.util.Base64;

import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.ResponseBuilder;

import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.ModelDuplicateException;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.services.ServicesLogger;

import waffle.util.AuthorizationHeader;
import waffle.windows.auth.IWindowsAuthProvider;
import waffle.windows.auth.IWindowsIdentity;
import waffle.windows.auth.IWindowsSecurityContext;
import waffle.windows.auth.impl.WindowsAuthProviderImpl;

/**
 * main implementation class, reworked for nginx compatibility
 * @author bogdan
 *
 */
public class KeycloakWaffleAuthenticator implements Authenticator {

    private static final String CONNECTION_SEPARATOR = ":";
	private static final String KEEP_ALIVE = "keep-alive";
	private static final String CONNECTION = "Connection";
	private static final String WWW_AUTHENTICATE2 = "WWW-Authenticate";
	private static final String NTLM2 = "NTLM ";
	private static final String NTLM = "NTLM";
	private static final String WWW_AUTHENTICATE = "WWW-AUTHENTICATE";
	private static final String AUTHORIZATION = "Authorization";
	private static final String X_FORWARDED_PORT = "X-Forwarded-Port";
	private static final String X_FORWARDED_FOR = "X-Forwarded-For";
	private final IWindowsAuthProvider auth = new WindowsAuthProviderImpl();	
       
    private String getRequestHeader(AuthenticationFlowContext context, String header) {
    	return context.getHttpRequest().getHttpHeaders().getRequestHeaders().getFirst(header);
    }
    
	/**
	 * modification due to proxy handling
	 * the X-Forwarded-Port header is set up to remote port, for nginx use:
	 * proxy_set_header X-Forwarded-Port     $remote_port;
	 */
	private IWindowsIdentity getNTLMIdentity(AuthenticationFlowContext context) throws IOException {
		//added by proxies
		String xForwarded = getRequestHeader(context, X_FORWARDED_FOR); //comma separated
		String xPort = getRequestHeader(context, X_FORWARDED_PORT); 	//if it contains : must split	
		String auth = getRequestHeader(context, AUTHORIZATION); 			
		if (auth == null) {
			Response response = Response.noContent().status(Response.Status.UNAUTHORIZED).header(WWW_AUTHENTICATE, NTLM).build();
        	context.challenge(response);
	        return null;
		}
		System.out.println("auth is " + auth);
		if (auth.startsWith(NTLM2)) {
			//waffle part
			final AuthorizationHeader authorizationHeader = new CustomAuthorizationHeader(context);
			final boolean ntlmPost = authorizationHeader.isNtlmType1PostAuthorizationHeader();
	        // maintain a connection-based session for NTLM tokens
			String connectionId = null;
			if(xForwarded != null && xPort != null) {
				connectionId = getConnectionId(xForwarded, xPort);
			} else {
				System.out.println("headers...");
				System.out.println(context.getConnection().getRemoteAddr());
				System.out.println(context.getConnection().getRemotePort());
				context.getHttpRequest().getHttpHeaders().getRequestHeaders().forEach((a, b) -> {
					System.out.println(a);
					System.out.println(b);
				});
				connectionId = String.join(CONNECTION_SEPARATOR, context.getConnection().getRemoteAddr(), String.valueOf(context.getConnection().getRemotePort()));
			}
	        
	        final String securityPackage = authorizationHeader.getSecurityPackage();			
			System.out.printf("security package: %s, connection id: %s\n", securityPackage, connectionId);
	        if (ntlmPost) {
	        	System.out.println("was ntlmPost");
	            // type 2 NTLM authentication message received
	            this.auth.resetSecurityToken(connectionId);
	        }

	        final byte[] tokenBuffer = authorizationHeader.getTokenBytes();
	        IWindowsSecurityContext securityContext = null;
	        try {
	        	 securityContext = this.auth.acceptSecurityToken(connectionId, tokenBuffer, securityPackage);
	        } catch (Exception e) {
				Response response = Response.noContent().status(Response.Status.UNAUTHORIZED).build();
	        	context.challenge(response);	        	
	        	//this can be context.cancelLogin();
	        	context.attempted();
		        return null;
	        }
	        final byte[] continueTokenBytes = securityContext.getToken();
	        ResponseBuilder responseBuilder = Response.noContent();
	        if (continueTokenBytes != null && continueTokenBytes.length > 0) {
	        	//type 2 message, the challenge
	            final String continueToken = Base64.getEncoder().encodeToString(continueTokenBytes);
	            responseBuilder.header(WWW_AUTHENTICATE2, securityPackage + " " + continueToken);
	        }
	        System.out.println("continue required: " + Boolean.valueOf(securityContext.isContinue()));
	        
	        if (securityContext.isContinue() || ntlmPost) {
	        	responseBuilder.header(CONNECTION, KEEP_ALIVE);
	        	responseBuilder.status(Response.Status.UNAUTHORIZED).build();
	        	context.challenge(responseBuilder.build());
	            return null;
	        }
	        final IWindowsIdentity identity = securityContext.getIdentity();
	        securityContext.dispose();
	        return identity;	
		}
		return null;
	}

	/**
	 * get connection id for proxy headers
	 * @param xForwarded
	 * @param xPort
	 * @return
	 */
	private String getConnectionId(String xForwarded, String xPort) {
		String host = xForwarded;
		String port = xPort;
		if(xForwarded.contains(",")) {
			host = xForwarded.split(",")[0];
		}
		if(port.contains(CONNECTION_SEPARATOR)) {
			String[] ports = xPort.split(CONNECTION_SEPARATOR);
			xPort = ports[ports.length -1];
		}
		return String.join(CONNECTION_SEPARATOR, host, port);
	}
	
	private String extractUserWithoutDomain(String username) {
		if(username.contains("\\")) {
			username = username.substring(username.indexOf("\\") + 1, username.length());
		}
		return username;
	}


    @Override
    public void authenticate(AuthenticationFlowContext context) {
        
        IWindowsIdentity identity = null;
		try {
			identity = getNTLMIdentity(context);
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return;
		}
		if(identity == null) 
			return;
        System.out.println("identity is " + identity.getFqn());
		//the fqn has the form domain\\user
        String username = extractUserWithoutDomain(identity.getFqn());
        UserModel user = null;
        try {
            user = KeycloakModelUtils.findUserByNameOrEmail(context.getSession(), context.getRealm(), username);
        } catch (ModelDuplicateException mde) {
            ServicesLogger.LOGGER.modelDuplicateException(mde);
            // Could happen during federation import
            return;
        }
        context.setUser(user);
        context.success();
        System.out.println("KeycloakWaffleAuthenticator :: authenticate :: success");   
    }

    @Override
    public boolean requiresUser() {
    	System.out.println("KeycloakWaffleAuthenticator :: requiresUser");
        //return true;
    	return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
    	System.out.println("KeycloakWaffleAuthenticator :: configuredFor");
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {
    	System.out.println("KeycloakWaffleAuthenticator :: setRequiredActions");
    }

    @Override
    public void close() {
    	System.out.println("KeycloakWaffleAuthenticator :: close");

    }

	@Override
	public void action(AuthenticationFlowContext context) {
		// TODO Auto-generated method stub
		
	}
}
