package io.authreporttool.core;

import java.util.List;

/**
 * The AuthorizationGroup class represents a collection of endpoints that share
 * the same authorization expression within the authorization report tool.
 *
 * This class serves as a way to organize and manage authorization information
 * for related endpoints, facilitating easier analysis and reporting of
 * authorization patterns across an application.
 */
public class AuthorizationGroup {

    /**
     * The authorization expression shared by all endpoints in this group.
     * This could be a Spring Security expression like "hasRole('ADMIN')" or
     * a custom authorization rule.
     */
    private final String authExpression;

    /**
     * A list of EndpointAuthInfo objects representing the endpoints that
     * share the same authorization expression.
     * This allows for grouping and analysis of endpoints with similar
     * authorization requirements.
     */
    private final List<EndpointAuthInfo> endpoints;

    /**
     * Constructs a new AuthorizationGroup with the specified authorization
     * expression and list of endpoints.
     *
     * @param authExpression The authorization expression (e.g., "hasRole('ADMIN')")
     *                       shared by all endpoints in this group.
     * @param endpoints A list of EndpointAuthInfo objects that share the same
     *                  authorization expression.
     */
    public AuthorizationGroup(String authExpression, List<EndpointAuthInfo> endpoints) {
        this.authExpression = authExpression;
        this.endpoints = endpoints;
    }

    /**
     * Retrieves the authorization expression for this group.
     *
     * @return The authorization expression shared by all endpoints in this group.
     */
    public String getAuthExpression() {
        return authExpression;
    }

    /**
     * Retrieves the list of endpoints in this authorization group.
     *
     * @return An unmodifiable list of EndpointAuthInfo objects belonging to this group.
     */
    public List<EndpointAuthInfo> getEndpoints() {
        return endpoints;
    }

    /**
     * Calculates and returns the number of endpoints in this authorization group.
     * This method provides a convenient way to get the size of the group without
     * directly accessing the endpoints list.
     *
     * @return The number of endpoints in this authorization group.
     */
    public int getEndpointCount() {
        return endpoints.size();
    }
}