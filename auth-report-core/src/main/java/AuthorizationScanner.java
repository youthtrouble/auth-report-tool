import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The AuthorizationScanner class is responsible for scanning a specified package
 * for REST controllers and extracting authentication and authorization details
 * for each endpoint.
 */
public class AuthorizationScanner {

    // Utility instance for performing reflection-based operations
    private final ReflectionUtils reflectionUtils;

    /**
     * Constructor to initialize the AuthorizationScanner with a ReflectionUtils instance.
     * @param reflectionUtils Utility class used for reflection-based operations.
     */
    public AuthorizationScanner(ReflectionUtils reflectionUtils) {
        this.reflectionUtils = reflectionUtils;
    }

    /**
     * Scans the specified base package for REST controllers and extracts
     * authentication and authorization details for each endpoint.
     * @param basePackage The base package to scan for controllers.
     * @return A list of EndpointAuthInfo containing authentication details for each endpoint.
     */
    public List<EndpointAuthInfo> scanApi(String basePackage) {
        // List to hold the authentication information for all endpoints
        List<EndpointAuthInfo> authInfoList = new ArrayList<>();

        // Use ReflectionUtils to find all classes annotated with @RestController in the specified package
        Set<Class<?>> controllers = reflectionUtils.findAnnotatedClasses(basePackage, RestController.class);

        // Iterate through each controller class
        for (Class<?> controller : controllers) {
            // Scan each controller and add the authentication details to the list
            authInfoList.addAll(scanController(controller));
        }

        // Return the list of authentication details
        return authInfoList;
    }

    /**
     * Scans the specified controller class for methods and extracts
     * authentication and authorization details for each method (endpoint).
     * @param controller The controller class to scan.
     * @return A list of EndpointAuthInfo containing authentication details for each method.
     */
    private List<EndpointAuthInfo> scanController(Class<?> controller) {
        // List to hold the authentication information for each method in the controller
        List<EndpointAuthInfo> authInfoList = new ArrayList<>();

        // Get all declared methods in the controller class
        Method[] methods = controller.getDeclaredMethods();

        // Iterate through each method to extract authentication information
        for (Method method : methods) {
            // Extract authentication information from the method
            EndpointAuthInfo authInfo = extractAuthInfo(method);
            // If authentication information is found, add it to the list
            if (authInfo != null) {
                authInfoList.add(authInfo);
            }
        }

        // Return the list of authentication details for the controller
        return authInfoList;
    }

    /**
     * Extracts authentication and authorization details from a given method.
     * @param method The method to extract authentication details from.
     * @return An EndpointAuthInfo object containing the authentication details, or null if not applicable.
     */
    private EndpointAuthInfo extractAuthInfo(Method method) {
        // Check if the method has a @RequestMapping annotation (or its derived annotations)
        RequestMapping methodMapping = method.getAnnotation(RequestMapping.class);

        // Check if the method has a @PreAuthorize annotation for authorization checks
        PreAuthorize preAuthorize = method.getAnnotation(PreAuthorize.class);

        // If the method is mapped to a URL path
        if (methodMapping != null) {
            // Determine the endpoint path from the method
            String path = determinePath(method);
            // Determine the HTTP method (GET, POST, etc.) from the method
            String httpMethod = determineHttpMethod(method);
            // Determine the authorization expression from the @PreAuthorize annotation (if present)
            String authExpression = (preAuthorize != null) ? preAuthorize.value() : "None";

            // Return the collected information as an EndpointAuthInfo object
            return new EndpointAuthInfo(path, httpMethod, authExpression);
        }

        // If the method is not mapped to a URL path, return null
        return null;
    }

    /**
     * Determines the URL path associated with a method based on the @RequestMapping annotation.
     * This method should handle various mapping annotations like @GetMapping, @PostMapping, etc.
     * @param method The method from which to extract the path.
     * @return The URL path as a String.
     */
    private String determinePath(Method method) {
        // Check for @GetMapping annotation
        GetMapping getMapping = method.getAnnotation(GetMapping.class);
        if (getMapping != null && getMapping.value().length > 0) {
            return getMapping.value()[0];
        }

        // Check for @PostMapping annotation
        PostMapping postMapping = method.getAnnotation(PostMapping.class);
        if (postMapping != null && postMapping.value().length > 0) {
            return postMapping.value()[0];
        }

        // Check for @PutMapping annotation
        PutMapping putMapping = method.getAnnotation(PutMapping.class);
        if (putMapping != null && putMapping.value().length > 0) {
            return putMapping.value()[0];
        }

        // Check for @DeleteMapping annotation
        DeleteMapping deleteMapping = method.getAnnotation(DeleteMapping.class);
        if (deleteMapping != null && deleteMapping.value().length > 0) {
            return deleteMapping.value()[0];
        }

        // Check for @RequestMapping annotation (as a fallback)
        RequestMapping requestMapping = method.getAnnotation(RequestMapping.class);
        if (requestMapping != null && requestMapping.value().length > 0) {
            return requestMapping.value()[0];
        }

        // Return an empty string or a default value if no path is found
        return "/";
    }

    /**
     * Determines the HTTP method (GET, POST, etc.) associated with a method
     * based on the @RequestMapping annotation or its derived annotations.
     * @param method The method from which to extract the HTTP method.
     * @return The HTTP method as a String (e.g., "GET", "POST").
     */
    private String determineHttpMethod(Method method) {
        // Check for @GetMapping annotation
        GetMapping getMapping = method.getAnnotation(GetMapping.class);
        if (getMapping != null) {
            return HttpMethod.GET.name();
        }

        // Check for @PostMapping annotation
        PostMapping postMapping = method.getAnnotation(PostMapping.class);
        if (postMapping != null) {
            return HttpMethod.POST.name();
        }

        // Check for @PutMapping annotation
        PutMapping putMapping = method.getAnnotation(PutMapping.class);
        if (putMapping != null) {
            return HttpMethod.PUT.name();
        }

        // Check for @DeleteMapping annotation
        DeleteMapping deleteMapping = method.getAnnotation(DeleteMapping.class);
        if (deleteMapping != null) {
            return HttpMethod.DELETE.name();
        }

        // Check for @RequestMapping annotation (as a fallback)
        RequestMapping requestMapping = method.getAnnotation(RequestMapping.class);
        if (requestMapping != null && requestMapping.method().length > 0) {
            return requestMapping.method()[0].name();
        }

        // Return a default value if no HTTP method is specified
        return HttpMethod.GET.name();
    }
}
