import java.util.Objects;

public class EndpointAuthInfo {

    private final String path;
    private final String httpMethod;
    private final String authExpression;

    /**
     * Constructor to initialize the EndpointAuthInfo object.
     * @param path The URL path of the endpoint.
     * @param httpMethod The HTTP method (GET, POST, etc.) of the endpoint.
     * @param authExpression The authorization expression (from @PreAuthorize) for the endpoint.
     */
    public EndpointAuthInfo(String path, String httpMethod, String authExpression) {
        this.path = path;
        this.httpMethod = httpMethod;
        this.authExpression = authExpression;
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
                '}';
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        EndpointAuthInfo that = (EndpointAuthInfo) o;
        return Objects.equals(path, that.path) &&
                Objects.equals(httpMethod, that.httpMethod) &&
                Objects.equals(authExpression, that.authExpression);
    }

    @Override
    public int hashCode() {
        return Objects.hash(path, httpMethod, authExpression);
    }


}
