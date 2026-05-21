package com.auth.service.util;

import com.auth.service.service.impl.LdapAuthenticationStrategy;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import javax.naming.Context;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;

@Component
public class LdapConnectionTester {

    private final LdapAuthenticationStrategy ldapAuthenticationStrategy;
    private final Logger logger = LoggerFactory.getLogger(LdapConnectionTester.class);

    @Value("${ldap.test.user.enabled:false}")
    private boolean testUserEnabled;

    @Value("${ldap.test.connection.enabled:false}")
    private boolean testConnectionEnabled;

    @Value("${ldap.test.username:}")
    private String testUsername;

    @Value("${ldap.test.password:}")
    private String testPassword;

    @Value("${ldap.url}")
    private String ldapUrl;

    @Value("${ldap.domain}")
    private String domain;

    @Value("${ldap.service.username}")
    private String serviceUsername;

    @Value("${ldap.service.password}")
    private String servicePassword;

    public LdapConnectionTester(LdapAuthenticationStrategy ldapAuthenticationStrategy) {
        this.ldapAuthenticationStrategy = ldapAuthenticationStrategy;
    }

    @PostConstruct
    public void testLdapConnection() {
        if (!testConnectionEnabled) {
            logger.info("LDAP connection test is disabled");
            return;
        }
        logger.info("Testing LDAP connection with service account...");

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, serviceUsername + "@" + domain);
        env.put(Context.SECURITY_CREDENTIALS, servicePassword);
        env.put(Context.REFERRAL, "follow");

        LdapContext ctx = null;
        try {
            // Try to establish connection with LDAP using service account
            ctx = new InitialLdapContext(env, null);
            logger.info("✅ LDAP CONNECTION SUCCESSFUL: Successfully connected to LDAP server using service account");
            logger.info("LDAP Server: {}", ldapUrl);
            logger.info("Service Account: {}", serviceUsername);
        } catch (javax.naming.CommunicationException e) {
            logger.error("❌ LDAP CONNECTION FAILED: Unable to reach LDAP server at {}", ldapUrl, e);
            logger.error("Please check if the LDAP server is running and accessible from this application");
        } catch (javax.naming.AuthenticationException e) {
            logger.error("❌ LDAP AUTHENTICATION FAILED: Service account credentials are invalid", e);
            logger.error("Service Account: {}", serviceUsername);
            logger.error("Please verify the service account credentials in your configuration");
        } catch (Exception e) {
            logger.error("❌ LDAP CONNECTION ERROR: Unexpected error during LDAP connection test", e);
        } finally {
            if (ctx != null) {
                try {
                    ctx.close();
                } catch (Exception e) {
                    logger.warn("Error closing LDAP context", e);
                }
            }
        }
    }

    @PostConstruct
    public void testUserLdapConnection() {
        if (!testUserEnabled) {
            logger.info("LDAP connection test is disabled");
            return;
        }

        try {
            logger.info("Testing LDAP connection with test credentials...");
            Authentication auth = ldapAuthenticationStrategy.authenticate(testUsername, testPassword);
            if (auth != null && auth.isAuthenticated()) {
                logger.info("LDAP connection test successful!");
                logger.info("Authenticated user: {}", auth.getName());
                logger.info("Authorities: {}", auth.getAuthorities());
            } else {
                logger.error("LDAP connection test failed: Authentication object is null or not authenticated");
            }
        } catch (Exception e) {
            logger.error("LDAP connection test failed with exception", e);
        }
    }
}