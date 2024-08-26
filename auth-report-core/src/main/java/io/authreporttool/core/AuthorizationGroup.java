package io.authreporttool.core;

import java.util.List;

/**
 * The io.authreporttool.core.AuthorizationGroup class represents a group of endpoints that share the same authorization expression.
 * It provides a way to organize and manage the authorization information for a set of related endpoints.
 */
public class AuthorizationGroup {

    /**
     * The authorization expression (e.g., "ROLE_ADMIN", "ROLE_USER") that the endpoints in this group share.
     */
    private final String authExpression;

    /**
     * The list of io.authreporttool.core.EndpointAuthInfo objects that belong to this authorization group.
     */
    private final List<EndpointAuthInfo> endpoints;

    /**
     * Constructor to initialize the io.authreporttool.core.AuthorizationGroup.
     * @param authExpression The authorization expression (e.g., "ROLE_ADMIN").
     * @param endpoints A list of io.authreporttool.core.EndpointAuthInfo objects that share the same authorization expression.
     */
    public AuthorizationGroup(String authExpression, List<EndpointAuthInfo> endpoints) {
        this.authExpression = authExpression;
        this.endpoints = endpoints;
    }

    /**
     * Getter method to retrieve the authorization expression for this group.
     * @return The authorization expression for this group.
     */
    public String getAuthExpression() {
        return authExpression;
    }

    /**
     * Getter method to retrieve the list of endpoints in this authorization group.
     * @return The list of io.authreporttool.core.EndpointAuthInfo objects that belong to this group.
     */
    public List<EndpointAuthInfo> getEndpoints() {
        return endpoints;
    }

    /**
     * Utility method to get the number of endpoints in this authorization group.
     * @return The number of endpoints in this authorization group.
     */
    public int getEndpointCount() {
        return endpoints.size();
    }
}