package io.authreporttool.core;

/**
 * The EndpointDiff class represents the difference between two versions of an endpoint's
 * authorization configuration. It is used in differential reporting to capture changes
 * in endpoint security settings over time.
 *
 * This class is immutable, ensuring thread-safety and preventing accidental modifications
 * after creation.
 */
public class EndpointDiff {

    /**
     * Represents the new (current) state of the endpoint's authorization configuration.
     * This will be null for endpoints that have been removed.
     */
    private final EndpointAuthInfo newEndpoint;

    /**
     * Represents the old (previous) state of the endpoint's authorization configuration.
     * This will be null for endpoints that have been newly added.
     */
    private final EndpointAuthInfo oldEndpoint;

    /**
     * Constructs a new EndpointDiff object.
     *
     * @param newEndpoint The new (current) endpoint authorization information.
     *                    This should be null if the endpoint has been removed.
     * @param oldEndpoint The old (previous) endpoint authorization information.
     *                    This should be null if the endpoint has been newly added.
     */
    public EndpointDiff(EndpointAuthInfo newEndpoint, EndpointAuthInfo oldEndpoint) {
        this.newEndpoint = newEndpoint;
        this.oldEndpoint = oldEndpoint;
    }

    /**
     * Retrieves the new (current) endpoint authorization information.
     *
     * @return The new EndpointAuthInfo, or null if the endpoint has been removed.
     */
    public EndpointAuthInfo getNewEndpoint() {
        return newEndpoint;
    }

    /**
     * Retrieves the old (previous) endpoint authorization information.
     *
     * @return The old EndpointAuthInfo, or null if the endpoint has been newly added.
     */
    public EndpointAuthInfo getOldEndpoint() {
        return oldEndpoint;
    }
}