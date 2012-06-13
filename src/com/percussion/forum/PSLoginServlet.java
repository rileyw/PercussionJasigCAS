package com.percussion.forum;

import com.percussion.security.PSAuthenticationFailedException;
import com.percussion.server.PSRequest;
import com.percussion.server.PSRequestParsingException;
import com.percussion.servlets.PSSecurityFilter;
import com.percussion.tools.PSURIEncoder;
import com.percussion.utils.request.PSRequestInfo;
import java.io.File;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import javax.security.auth.login.LoginException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.apache.commons.lang.ObjectUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jasig.cas.client.jaas.AssertionPrincipal;

/**
 * PSLoginServlet adds the necessary logic to enable Jasig Central
 * Authentication Services while still supporting the default
 * com.percussion.servlets.PSLoginServlet behavior.
 * 
 * @author rileyw
 */
public class PSLoginServlet extends HttpServlet {
	private static final long serialVersionUID = 5331045574692416814L;

	public static final String REDIRECT_URL = "RX_REDIRECT_URL";
	private static Log log = LogFactory.getLog(PSLoginServlet.class);

	/**
	 * Initial request handling
	 * 
	 * @see javax.servlet.http.HttpServlet#service(javax.servlet.http.HttpServletRequest,
	 *      javax.servlet.http.HttpServletResponse)
	 */
	protected void service(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {
		String servletPath = request.getServletPath();
		if ("/login".equals(servletPath)) {
			doLogin(request, response);
		} else {
			if (!"/logout".equals(servletPath))
				return;
			doLogout(request, response);
		}
	}

	/**
	 * addRedirect generates
	 * 
	 * @param request
	 * @param loginPage
	 * @return String
	 */
	public static String addRedirect(HttpServletRequest request,
			String loginPage) {
		if (request == null)
			throw new IllegalArgumentException(
					"HttpServletRequest cannot be null");
		if (StringUtils.isBlank(loginPage))
			throw new IllegalArgumentException(
					"loginPage cannot be null or empty");
		String sysRedirect = null;
		try {
			sysRedirect = request.getRequestURL().toString();
		} catch (NullPointerException localNullPointerException) {
			sysRedirect = "/Rhythmyx/index.jsp";
		}
		String delimiter = "?";
		if (sysRedirect.endsWith(loginPage))
			sysRedirect = "/Rhythmyx/index.jsp";
		else if (request.getQueryString() != null)
			sysRedirect = sysRedirect + delimiter + request.getQueryString();
		loginPage = loginPage + delimiter + "sys_redirect" + "="
				+ PSURIEncoder.escape(sysRedirect);
		return loginPage;
	}

	/**
	 * doLogout performs the logout procedure
	 * 
	 * @param request
	 * @param response
	 * @throws IOException
	 * @throws ServletException
	 */
	private void doLogout(HttpServletRequest request,
			HttpServletResponse response) throws IOException, ServletException {
		HttpSession session = request.getSession();
		if (session != null)
			PSSecurityFilter.logout(request,
					(String) session.getAttribute("pssessionid"));
		response.setContentType("text/html;charset=UTF-8");
		request.getRequestDispatcher(getLogoutJSP()).include(request, response);
	}

	/**
	 * 
	 * doLogin performs the login procedure
	 * 
	 * @param request
	 * @param response
	 * @throws ServletException
	 * @throws IOException
	 */
	private void doLogin(HttpServletRequest request,
			HttpServletResponse response) throws ServletException, IOException {

		/**
		 * Initialize username and password
		 */
		String username = null;
		String password = null;

		/**
		 * Data handling for default login form
		 */
		if (request.getMethod().equalsIgnoreCase("POST")) {
			PSRequest loginData = (PSRequest) PSRequestInfo
					.getRequestInfo("PSREQUEST");
			if (loginData == null)
				throw new RuntimeException(
						"The request was not properly initialized by the security filter");
			try {
				((PSRequest) loginData).parseBody();
				username = ((PSRequest) loginData).getParameter("j_username");
				password = ((PSRequest) loginData).getParameter("j_password");
			} catch (PSRequestParsingException e) {
				throw new ServletException(e);
			}
		} else {
			if (request.getUserPrincipal() instanceof AssertionPrincipal) {
				username = request.getRequestURL()+"?"+request.getQueryString();
				password = request.getParameter("ticket");
            } else {
            	log.debug("Aborting -- principal is not of type AssertionPrincipal");
            }
		}
		Object sysRedirect = request.getParameter("sys_redirect");
		if (isValidRedirect(request, (String) sysRedirect))
			request.getSession().setAttribute(REDIRECT_URL, sysRedirect);

		/**
		 * Request handling
		 */
		if (!(StringUtils.isBlank(username))) {
			authenticate(request, response, username, password);
		} else {
			response.setContentType("text/html;charset=UTF-8");
			request.getRequestDispatcher(getLoginJSP()).include(request,
					response);
		}
	}

	/**
	 * isValidRedirect performs the required validation to confirm whether the
	 * provided request and redirect is valid.
	 * 
	 * @param request
	 * @param paramString
	 * @return
	 */
	protected static boolean isValidRedirect(HttpServletRequest request,
			String sysRedirect) {
		int i = 0;
		if (StringUtils.isBlank(sysRedirect))
			return false;
		try {
			URI sysRedirectURI = new URI(sysRedirect);
			if ((sysRedirectURI.getHost() == null)
					&& (sysRedirectURI.getAuthority() == null)
					&& (sysRedirectURI.getScheme() == null)
					&& (StringUtils.isNotBlank(sysRedirectURI.getPath()))) {
				i = 1;
			} else {
				URI requestURI = new URI(request.getRequestURL().toString());
				i = ((ObjectUtils.equals(requestURI.getHost(),
						requestURI.getHost()))
						&& (ObjectUtils.equals(
								Integer.valueOf(requestURI.getPort()),
								Integer.valueOf(sysRedirectURI.getPort()))) && (ObjectUtils
						.equals(requestURI.getScheme(),
								sysRedirectURI.getScheme()))) ? 1 : 0;
			}
		} catch (URISyntaxException URISyntaxException) {
			log.error("Bad redirect uri: " + sysRedirect, URISyntaxException);
			i = 0;
		}
		if (i == 0)
			log.error("Bad redirect uri: " + sysRedirect);
		return ("0".equals(i)) ? false : true;
	}

	/**
	 * authenticate initiates PSSecurity.authenticate
	 * @param request
	 * @param response
	 * @param username
	 * @param password
	 * @throws IOException
	 * @throws ServletException
	 */
	private void authenticate(HttpServletRequest request,
			HttpServletResponse response, String username, String password)
			throws IOException, ServletException {
		Object sysRedirect;
		try {
			HttpSession session = request.getSession(true);
			sysRedirect = (String) session.getAttribute(REDIRECT_URL);
			if (sysRedirect == null)
				sysRedirect = "/Rhythmyx/index.jsp";
			request = PSSecurityFilter.authenticate(request, response,
					username, password);

			/**
			 * Redirecting the response to the Rhythmyx servlet
			 */
			response.sendRedirect((String) sysRedirect);
			session.removeAttribute(REDIRECT_URL);
		} catch (LoginException loginException) {
			sysRedirect = new PSAuthenticationFailedException(9021, null);
			String msg = ((PSAuthenticationFailedException) sysRedirect)
					.getLocalizedMessage();
			log.debug(msg, loginException);
			request = new HttpServletRequestWrapper(request) {
				private String var;

				public String getParameter(String arg) {
					if ("j_error".equals(arg))
						return this.var;
					return super.getParameter(arg);
				}
			};
			response.setContentType("text/html;charset=UTF-8");
			request.getRequestDispatcher(getErrorJSP()).include(request,
					response);
		}
	}

	private String getErrorJSP() {
		File localFile = new File(getJSPPath(), "error.jsp");
		if (localFile.exists())
			return "/user/error.jsp";
		return getLoginJSP();
	}

	private String getLoginJSP() {
		File localFile = new File(getJSPPath(), "login.jsp");
		if (localFile.exists())
			return "/user/login.jsp";
		return "/rxlogin.jsp";
	}

	private String getLogoutJSP() {
		File localFile = new File(getJSPPath(), "logout.jsp");
		if (localFile.exists())
			return "user/logout.jsp";
		return "rxlogout.jsp";
	}

	private File getJSPPath() {
		return new File(getPath(), "user");
	}

	private File getPath() {
		return new File(getServletContext().getRealPath("/"));
	}
}