package io.authreporttool.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.*;

public class EndpointAuthInfo {

    private static final Logger log = LoggerFactory.getLogger(EndpointAuthInfo.class);
    private final String path;
    private final String httpMethod;
    private final String authExpression;
    private final String methodName;
    private final String className;
    private boolean apiKeyRequired;
    private boolean basicAuthRequired;
    private List<String> roles;
    private String apiKeyHeaderName;
    private Set<String> securityFeatures;

    /**
     * Constructor to initialize the io.authreporttool.core.EndpointAuthInfo object.
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

    public void setSessionManagement(String sessionManagement) {
        log.debug("adding session management 🚨");
        addSecurityFeature("Session Management: " + sessionManagement);

        log.debug("Security features 🫠: {}", securityFeatures);
    }

    public Object isBasicAuthRequired() {
        return basicAuthRequired;
    }

    public Object isCsrfEnabled() {
        return securityFeatures.contains("CSRF Protection");
    }

    public Object getSessionManagement() {
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
