package io.authreporttool.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

/**
 * The EndpointAuthInfo class encapsulates detailed authentication and authorization
 * information for a single API endpoint. It serves as a comprehensive data structure
 * to store and manage various security aspects of an endpoint, including its path,
 * HTTP method, authorization requirements, and applied security features.
 */
public class EndpointAuthInfo {

    private static final Logger log = LoggerFactory.getLogger(EndpointAuthInfo.class);

    // Core endpoint information
    private final String path;
    private final String httpMethod;
    private final String authExpression;
    private final String methodName;
    private final String className;

    // Authentication requirements
    private boolean apiKeyRequired;
    private boolean basicAuthRequired;
    private List<String> roles;
    private String apiKeyHeaderName;

    // Security features
    private Set<String> securityFeatures;

    /**
     * Constructs a new EndpointAuthInfo with the specified core information.
     *
     * @param path The URL path of the endpoint.
     * @param httpMethod The HTTP method (GET, POST, etc.) of the endpoint.
     * @param authExpression The authorization expression (from @PreAuthorize) for the endpoint.
     * @param methodName The name of the method associated with the endpoint.
     * @param className The name of the class containing the method.
     */
    public EndpointAuthInfo(String path, String httpMethod, String authExpression, String methodName, String className) {
        this.path = path;
        this.httpMethod = httpMethod;
        this.authExpression = authExpression;
        this.methodName = methodName;
        this.className = className;
        this.apiKeyRequired = false;
        this.apiKeyHeaderName = null;
        this.securityFeatures = new HashSet<>();
    }

    /**
     * Default constructor creating an empty EndpointAuthInfo.
     * Primarily used for testing or when details will be populated later.
     */
    public EndpointAuthInfo() {
        this.path = null;
        this.httpMethod = null;
        this.authExpression = null;
        this.methodName = null;
        this.className = null;
        this.apiKeyRequired = false;
        this.apiKeyHeaderName = null;
        this.securityFeatures = new HashSet<>();
    }

    /**
     * Copy constructor to create a new EndpointAuthInfo object from an existing one.
     *
     * @param authInfo The existing EndpointAuthInfo object to copy.
     */
    public EndpointAuthInfo(EndpointAuthInfo authInfo) {
        this.path = authInfo.path;
        this.httpMethod = authInfo.httpMethod;
        this.authExpression = authInfo.authExpression;
        this.methodName = authInfo.methodName;
        this.className = authInfo.className;
        this.apiKeyRequired = authInfo.apiKeyRequired;
        this.apiKeyHeaderName = authInfo.apiKeyHeaderName;
        this.securityFeatures = new HashSet<>(authInfo.securityFeatures);
    }

    // Getter methods

    public String getPath() {
        return path;
    }

    public String getHttpMethod() {
        return httpMethod;
    }

    public String getAuthExpression() {
        return authExpression;
    }

    public boolean isApiKeyRequired() {
        return apiKeyRequired;
    }

    // Setter methods

    public void setApiKeyRequired(boolean apiKeyRequired) {
        this.apiKeyRequired = apiKeyRequired;
    }

    public void setBasicAuthRequired(boolean basicAuthRequired) {
        log.debug("Setting basic auth required: {}", basicAuthRequired);
        this.basicAuthRequired = basicAuthRequired;
    }

    public void setSecurityFeatures(Set<String> securityFeatures) {
        log.debug("Setting security features: {}", securityFeatures);
        this.securityFeatures = securityFeatures;
    }

    public void addSecurityFeature(String feature) {
        this.securityFeatures.add(feature);
    }

    /**
     * Sets the session management type and adds it as a security feature.
     *
     * @param sessionManagement The type of session management being used.
     */
    public void setSessionManagement(String sessionManagement) {
        log.debug("Adding session management 🚨");
        addSecurityFeature("Session Management: " + sessionManagement);
        log.debug("Security features 🫠: {}", securityFeatures);
    }

    public boolean isBasicAuthRequired() {
        return basicAuthRequired;
    }

    /**
     * Checks if CSRF protection is enabled for this endpoint.
     *
     * @return true if CSRF protection is enabled, false otherwise.
     */
    public Object isCsrfEnabled() {
        return securityFeatures.contains("CSRF Protection");
    }

    /**
     * Retrieves the session management type if set.
     *
     * @return The session management type, or null if not set.
     */
    public String getSessionManagement() {
        return securityFeatures.stream()
                .filter(f -> f.startsWith("Session Management"))
                .findFirst()
                .orElse(null);
    }

    public Set<String> getSecurityFeatures() {
        return securityFeatures;
    }

    @Override
    public String toString() {
        return "EndpointAuthInfo{" +
                "path='" + path + '\'' +
                ", httpMethod='" + httpMethod + '\'' +
                ", authExpression='" + authExpression + '\'' +
                ", methodName='" + methodName + '\'' +
                ", className='" + className + '\'' +
                ", apiKeyRequired=" + apiKeyRequired +
                ", basicAuthRequired=" + basicAuthRequired +
                ", roles=" + roles +
                ", apiKeyHeaderName='" + apiKeyHeaderName + '\'' +
                ", securityFeatures=" + securityFeatures +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EndpointAuthInfo that = (EndpointAuthInfo) o;
        return apiKeyRequired == that.apiKeyRequired &&
                path.equals(that.path) &&
                httpMethod.equals(that.httpMethod) &&
                authExpression.equals(that.authExpression) &&
                methodName.equals(that.methodName) &&
                className.equals(that.className) &&
                Objects.equals(apiKeyHeaderName, that.apiKeyHeaderName);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, httpMethod, authExpression, methodName, className, apiKeyRequired, apiKeyHeaderName);
    }
}