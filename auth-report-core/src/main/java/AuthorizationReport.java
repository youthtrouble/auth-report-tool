import java.time.LocalDateTime;
import java.util.List;

/**
 * The AuthorizationReport class represents a structured report of the authorization information
 * collected by the AuthorizationScanner. It provides a hierarchical view of the authorization
 * requirements for the scanned API endpoints.
 */
public class AuthorizationReport {

    /**
     * A list of AuthorizationGroup objects, where each group represents a set of endpoints
     * that share the same authorization expression (e.g., "ROLE_ADMIN", "ROLE_USER").
     */
    private final List<AuthorizationGroup> groups;

    /**
     * The timestamp when the authorization report was generated.
     */
    private final LocalDateTime generatedAt;

    /**
     * Constructor to initialize the AuthorizationReport.
     * @param groups A list of AuthorizationGroup objects representing the grouped authorization information.
     * @param generatedAt The timestamp when the report was generated.
     */
    public AuthorizationReport(List<AuthorizationGroup> groups, LocalDateTime generatedAt) {
        this.groups = groups;
        this.generatedAt = generatedAt;
    }

    /**
     * Getter method to retrieve the list of AuthorizationGroup objects in the report.
     * @return The list of AuthorizationGroup objects.
     */
    public List<AuthorizationGroup> getGroupedEndpoints() {
        return groups;
    }

    /**
     * Getter method to retrieve the timestamp when the report was generated.
     * @return The timestamp when the report was generated.
     */
    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    /**
     * Utility method to get the total number of endpoints in the report.
     * @return The total number of endpoints in the report.
     */
    public int getTotalEndpoints() {
        return groups.stream()
                .mapToInt(AuthorizationGroup::getEndpointCount)
                .sum();
    }

    /**
     * Utility method to get the number of unique authorization expressions in the report.
     * @return The number of unique authorization expressions in the report.
     */
    public int getUniqueAuthExpressions() {
        return groups.size();
    }
}