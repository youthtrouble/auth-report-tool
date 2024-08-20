import java.util.List;

public class DifferentialReport {

    private final List<EndpointDiff> addedEndpoints;
    private final List<EndpointDiff> removedEndpoints;
    private final List<EndpointDiff> changedEndpoints;

    /**
     * Constructor to initialize the DifferentialReport.
     * @param addedEndpoints A list of EndpointDiff objects representing added endpoints.
     * @param removedEndpoints A list of EndpointDiff objects representing removed endpoints.
     * @param changedEndpoints A list of EndpointDiff objects representing changed endpoints.
     */
    public DifferentialReport(List<EndpointDiff> addedEndpoints, List<EndpointDiff> removedEndpoints, List<EndpointDiff> changedEndpoints) {
        this.addedEndpoints = addedEndpoints;
        this.removedEndpoints = removedEndpoints;
        this.changedEndpoints = changedEndpoints;
    }

// Get
    public List<EndpointDiff> getAddedEndpoints() {
        return addedEndpoints;
    }

    public List<EndpointDiff> getRemovedEndpoints() {
        return removedEndpoints;
    }

    public List<EndpointDiff> getChangedEndpoints() {
        return changedEndpoints;
    }
}