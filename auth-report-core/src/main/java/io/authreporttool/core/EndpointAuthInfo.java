package io.authreporttool.core;

import java.util.Objects;

public class EndpointAuthInfo {

    private final String path;
    private final String httpMethod;
    private final String authExpression;
    private final String methodName;
    private final String className;

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

    @Override
    public String toString() {
        return "EndpointAuthInfo{" +
                "path='" + path + '\'' +
                ", httpMethod='" + httpMethod + '\'' +
                ", authExpression='" + authExpression + '\'' +
                ", methodName='" + methodName + '\'' +
                ", className='" + className + '\'' +
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EndpointAuthInfo that = (EndpointAuthInfo) o;
        return Objects.equals(path, that.path) &&
                Objects.equals(httpMethod, that.httpMethod) &&
                Objects.equals(authExpression, that.authExpression) &&
                Objects.equals(methodName, that.methodName) &&
                Objects.equals(className, that.className);
    }


    @Override
    public int hashCode() {
        return Objects.hash(path, httpMethod, authExpression);
    }

    public String getMethodName() {
        return methodName;
    }

    public String getClassName() {
        return className;
    }

    //From the EndpointAuthInfo class, the methods getMethodName and getClassName are not accounted for in the class and in the core scanning implementation. Can you fix this. Dig into your memory to find the other classes.
}
