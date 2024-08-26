package io.authreporttool.core;

public class EndpointDiff {
    private final EndpointAuthInfo newEndpoint;
    private final EndpointAuthInfo oldEndpoint;

    public EndpointDiff(EndpointAuthInfo newEndpoint, EndpointAuthInfo oldEndpoint) {
        this.newEndpoint = newEndpoint;
        this.oldEndpoint = oldEndpoint;
    }

    public EndpointAuthInfo getNewEndpoint() {
        return newEndpoint;
    }

    public EndpointAuthInfo getOldEndpoint() {
        return oldEndpoint;
    }
}