package com.auth.service.service.impl;

import com.auth.service.exception.LdapException;
import com.auth.service.service.AuthenticationStrategy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;

@Component
public class LdapAuthenticationStrategy implements AuthenticationStrategy {

    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticationStrategy.class);

    @Value("${ldap.url}")
    private String ldapUrl;

    @Value("${ldap.domain}")
    private String domain;

    @Value("${ldap.user.search.base}")
    private String userSearchBase;

    @Value("${ldap.group.search.base}")
    private String groupSearchBase;

    @Value("${ldap.service.username}")
    private String serviceUsername;

    @Value("${ldap.service.password}")
    private String servicePassword;

    @Override
    public Authentication authenticate(String username, String password) {
        logger.info("LDAP authentication request received for username: {}", username);

        // First, establish connection using service account
        LdapContext serviceContext = getServiceContext();

        try {
            // Verify if the user exists and get their DN
            String userDn = findUserDn(serviceContext, username);
            if (userDn == null) {
                logger.error("User not found: {}", username);
                throw LdapException.authenticationFailed("User not found");
            }

            // Now try to authenticate with the user's credentials
            if (!validateUserCredentials(userDn, password)) {
                logger.error("Invalid credentials for user: {}", username);
                throw LdapException.authenticationFailed("Invalid credentials");
            }

            // If we get here, authentication was successful
            // Fetch user roles from LDAP groups
            List<SimpleGrantedAuthority> authorities = getLdapUserAuthorities(serviceContext, userDn);

            return new UsernamePasswordAuthenticationToken(username, null, authorities);
        } finally {
            closeContext(serviceContext);
        }
    }

    private LdapContext getServiceContext() {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, serviceUsername + "@" + domain);
        env.put(Context.SECURITY_CREDENTIALS, servicePassword);
        env.put(Context.REFERRAL, "follow");

        try {
            return new InitialLdapContext(env, null);
        } catch (javax.naming.CommunicationException e) {
            logger.error("LDAP connection failed", e);
            throw LdapException.connectionFailed("Unable to establish connection with the LDAP server: " + e.getMessage());
        } catch (Exception e) {
            logger.error("Unexpected error during LDAP connection", e);
            throw LdapException.connectionFailed("LDAP connection failed: " + e.getMessage());
        }
    }

    private String findUserDn(LdapContext ctx, String username) {
        try {
            String searchFilter = "(sAMAccountName=" + username + ")";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> results = ctx.search(userSearchBase, searchFilter, searchControls);

            if (results.hasMore()) {
                SearchResult result = results.next();
                return result.getNameInNamespace();
            }
            return null;
        } catch (Exception e) {
            logger.error("Error finding user DN for: {}", username, e);
            return null;
        }
    }

    private boolean validateUserCredentials(String userDn, String password) {
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);
        env.put(Context.SECURITY_AUTHENTICATION, "simple");
        env.put(Context.SECURITY_PRINCIPAL, userDn);
        env.put(Context.SECURITY_CREDENTIALS, password);

        LdapContext ctx = null;
        try {
            ctx = new InitialLdapContext(env, null);
            return true;
        } catch (javax.naming.AuthenticationException e) {
            return false;
        } catch (Exception e) {
            logger.error("Error validating user credentials", e);
            return false;
        } finally {
            closeContext(ctx);
        }
    }

    private List<SimpleGrantedAuthority> getLdapUserAuthorities(LdapContext ctx, String userDn) {
        List<SimpleGrantedAuthority> authorities = new ArrayList<>();

        try {
            // Search for groups that contain this user
            String groupFilter = "(member=" + userDn + ")";
            SearchControls searchControls = new SearchControls();
            searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

            NamingEnumeration<SearchResult> groupResults = ctx.search(groupSearchBase, groupFilter, searchControls);

            while (groupResults.hasMore()) {
                SearchResult result = groupResults.next();
                Attributes attrs = result.getAttributes();
                if (attrs.get("cn") != null) {
                    String groupName = attrs.get("cn").get().toString();
                    authorities.add(new SimpleGrantedAuthority("ROLE_" + groupName.toUpperCase()));
                    logger.debug("Added authority ROLE_{} for user {}", groupName.toUpperCase(), userDn);
                }
            }
        } catch (Exception e) {
            logger.warn("Failed to fetch groups for user: {}", userDn, e);
        }

        if (authorities.isEmpty()) {
            logger.warn("No authorities found for user: {}, adding default authority", userDn);
            authorities.add(new SimpleGrantedAuthority("ROLE_USER"));
        }

        return authorities;
    }

    private void closeContext(LdapContext ctx) {
        if (ctx != null) {
            try {
                ctx.close();
            } catch (Exception e) {
                logger.warn("Error closing LDAP context", e);
            }
        }
    }
}