package io.authreporttool.core;

import java.time.LocalDateTime;
import java.util.List;

/**
 * The AuthorizationReport class encapsulates the complete authorization analysis
 * of an API, as performed by the AuthorizationScanner. It provides a structured,
 * hierarchical view of the authorization requirements for all scanned API endpoints.
 *
 * This class serves as the main data structure for representing the final output
 * of the authorization scanning process, offering methods to access grouped
 * endpoint information and overall statistics about the scanned API's
 * authorization landscape.
 */
public class AuthorizationReport {

    /**
     * A list of AuthorizationGroup objects, each representing a set of endpoints
     * that share the same authorization expression (e.g., "hasRole('ADMIN')").
     * This grouping allows for easy analysis of authorization patterns across
     * the API.
     */
    private final List<AuthorizationGroup> groups;

    /**
     * The timestamp indicating when this authorization report was generated.
     * This information is crucial for versioning and tracking changes in
     * authorization configurations over time.
     */
    private final LocalDateTime generatedAt;

    /**
     * Constructs a new AuthorizationReport with the specified groups of
     * endpoints and generation timestamp.
     *
     * @param groups A list of AuthorizationGroup objects representing the
     *               grouped authorization information for all scanned endpoints.
     * @param generatedAt The timestamp when this report was generated.
     */
    public AuthorizationReport(List<AuthorizationGroup> groups, LocalDateTime generatedAt) {
        this.groups = groups;
        this.generatedAt = generatedAt;
    }

    /**
     * Retrieves the list of AuthorizationGroup objects in the report.
     * Each group represents a set of endpoints sharing the same
     * authorization expression.
     *
     * @return An unmodifiable list of AuthorizationGroup objects.
     */
    public List<AuthorizationGroup> getGroupedEndpoints() {
        return groups;
    }

    /**
     * Retrieves the timestamp when this report was generated.
     *
     * @return The LocalDateTime representing when this report was created.
     */
    public LocalDateTime getGeneratedAt() {
        return generatedAt;
    }

    /**
     * Calculates and returns the total number of endpoints analyzed in this report.
     * This method aggregates the endpoint counts across all authorization groups.
     *
     * @return The total number of endpoints in the report.
     */
    public int getTotalEndpoints() {
        return groups.stream()
                .mapToInt(AuthorizationGroup::getEndpointCount)
                .sum();
    }

    /**
     * Calculates and returns the number of unique authorization expressions
     * found across all endpoints in the API.
     * This is equivalent to the number of AuthorizationGroup objects in the report.
     *
     * @return The number of unique authorization expressions in the report.
     */
    public int getUniqueAuthExpressions() {
        return groups.size();
    }
}