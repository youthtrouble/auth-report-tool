package io.authreporttool.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.bind.annotation.*;

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * The AuthorizationScanner class is responsible for scanning a specified package
 * for REST controllers and security configurations to extract authentication and
 * authorization details for each endpoint, including API key authentication.
 */
public class AuthorizationScanner {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationScanner.class);

    // Utility instance for performing reflection-based operations
    private final ReflectionUtils reflectionUtils;
    private final SecurityConfigAnalyzer securityConfigAnalyzer;

    /**
     * Constructor to initialize the AuthorizationScanner with a ReflectionUtils instance.
     * @param reflectionUtils Utility class used for reflection-based operations.
     */
    public AuthorizationScanner(ReflectionUtils reflectionUtils, SecurityConfigAnalyzer securityConfigAnalyzer) {
        this.reflectionUtils = reflectionUtils;
        this.securityConfigAnalyzer = securityConfigAnalyzer;
    }

    /**
     * Scans the specified base package for REST controllers and security configurations,
     * and extracts authentication and authorization details for each endpoint.
     * @param basePackage The base package to scan for controllers and security config.
     * @return A list of EndpointAuthInfo containing authentication details for each endpoint.
     */
    public List<EndpointAuthInfo> scanApi(String basePackage) {
        List<EndpointAuthInfo> authInfoList = new ArrayList<>();

        try {
            // Scan for REST controllers
            Set<Class<?>> controllers = reflectionUtils.findAnnotatedClasses(basePackage, RestController.class);

            logger.info("scanned controllers: " + controllers.size());
            for (Class<?> controller : controllers) {
                logger.info("Scanning controller: " + controller.getName());
                authInfoList.addAll(scanController(controller));
            }

            // Scan for security configuration
            Set<Class<?>> securityConfigs = reflectionUtils.findClassesWithBeanMethods(basePackage, SecurityFilterChain.class);
            for (Class<?> config : securityConfigs) {
                logger.info("Scanning security config(Bean methods): " + config.getName());
                scanSecurityConfig(config, authInfoList);
            }
        } catch (Exception e) {
            logger.error("Error occurred while scanning API", e);
        }

        return authInfoList;
    }

    /**
     * Scans the specified controller class for methods and extracts
     * authentication and authorization details for each method (endpoint).
     * @param controller The controller class to scan.
     * @return A list of EndpointAuthInfo containing authentication details for each method.
     */
    private List<EndpointAuthInfo> scanController(Class<?> controller) {
        List<EndpointAuthInfo> authInfoList = new ArrayList<>();
        String controllerPath = extractControllerPath(controller);

        for (Method method : controller.getDeclaredMethods()) {
            try {
                logger.info("Scanning method: " + method.getName());
                EndpointAuthInfo authInfo = extractAuthInfo(method, controllerPath);
                if (authInfo != null) {
                    authInfoList.add(authInfo);
                }
            } catch (Exception e) {
                logger.warn("Error extracting auth info for method: " + method.getName(), e);
            }
        }

        return authInfoList;
    }

    /**
     * Extracts the base path for the controller from its RequestMapping annotation.
     * @param controller The controller class.
     * @return The base path for the controller, or an empty string if not found.
     */
    private String extractControllerPath(Class<?> controller) {
        RequestMapping mapping = controller.getAnnotation(RequestMapping.class);
        if (mapping != null && mapping.value().length > 0) {
            return mapping.value()[0];
        }
        return "";
    }

    /**
     * Extracts authentication and authorization details from a given method.
     * @param method The method to extract authentication details from.
     * @param controllerPath The base path of the controller.
     * @return An EndpointAuthInfo object containing the authentication details, or null if not applicable.
     */
    private EndpointAuthInfo extractAuthInfo(Method method, String controllerPath) {
        RequestMapping methodMapping = method.getAnnotation(RequestMapping.class);
        GetMapping getMapping = method.getAnnotation(GetMapping.class);
        PostMapping postMapping = method.getAnnotation(PostMapping.class);
        PutMapping putMapping = method.getAnnotation(PutMapping.class);
        DeleteMapping deleteMapping = method.getAnnotation(DeleteMapping.class);
        PreAuthorize preAuthorize = method.getAnnotation(PreAuthorize.class);

        if (methodMapping != null || getMapping != null || postMapping != null || putMapping != null || deleteMapping != null) {
            String path = determinePath(method, controllerPath);
            String httpMethod = determineHttpMethod(method);
            String authExpression = (preAuthorize != null) ? preAuthorize.value() : "None";
            String methodName = method.getName();
            String className = method.getDeclaringClass().getName();

            return new EndpointAuthInfo(path, httpMethod, authExpression, methodName, className);
        }

        return null;
    }

    /**
     * Determines the full path for an endpoint.
     * @param method The method representing the endpoint.
     * @param controllerPath The base path of the controller.
     * @return The full path of the endpoint.
     */
    private String determinePath(Method method, String controllerPath) {
        String methodPath = "";

        if (method.isAnnotationPresent(RequestMapping.class)) {
            RequestMapping mapping = method.getAnnotation(RequestMapping.class);
            methodPath = mapping.value().length > 0 ? mapping.value()[0] : "";
        } else if (method.isAnnotationPresent(GetMapping.class)) {
            GetMapping mapping = method.getAnnotation(GetMapping.class);
            methodPath = mapping.value().length > 0 ? mapping.value()[0] : "";
        } else if (method.isAnnotationPresent(PostMapping.class)) {
            PostMapping mapping = method.getAnnotation(PostMapping.class);
            methodPath = mapping.value().length > 0 ? mapping.value()[0] : "";
        } else if (method.isAnnotationPresent(PutMapping.class)) {
            PutMapping mapping = method.getAnnotation(PutMapping.class);
            methodPath = mapping.value().length > 0 ? mapping.value()[0] : "";
        } else if (method.isAnnotationPresent(DeleteMapping.class)) {
            DeleteMapping mapping = method.getAnnotation(DeleteMapping.class);
            methodPath = mapping.value().length > 0 ? mapping.value()[0] : "";
        }

        return (controllerPath + methodPath).replaceAll("//", "/");
    }

    /**
     * Determines the HTTP method for an endpoint.
     * @param method The method representing the endpoint.
     * @return The HTTP method as a string.
     */
    private String determineHttpMethod(Method method) {
        if (AnnotationUtils.findAnnotation(method, GetMapping.class) != null) return HttpMethod.GET.name();
        if (AnnotationUtils.findAnnotation(method, PostMapping.class) != null) return HttpMethod.POST.name();
        if (AnnotationUtils.findAnnotation(method, PutMapping.class) != null) return HttpMethod.PUT.name();
        if (AnnotationUtils.findAnnotation(method, DeleteMapping.class) != null) return HttpMethod.DELETE.name();
        RequestMapping requestMapping = AnnotationUtils.findAnnotation(method, RequestMapping.class);
        if (requestMapping != null) {
            return requestMapping.method().length > 0 ? requestMapping.method()[0].name() : HttpMethod.GET.name();
        }
        return HttpMethod.GET.name();
    }

    private void scanSecurityConfig(Class<?> configClass, List<EndpointAuthInfo> authInfoList) {
        for (Method method : configClass.getDeclaredMethods()) {
            if (SecurityFilterChain.class.isAssignableFrom(method.getReturnType())) {
                for (EndpointAuthInfo authInfo : authInfoList) {
                    logger.info("Analyzing SecurityFilterChain method(outward scanner): {}", method.getName());
                    securityConfigAnalyzer.analyzeSecurityFilterChain(method, authInfo);
                }
            }
        }
    }
}