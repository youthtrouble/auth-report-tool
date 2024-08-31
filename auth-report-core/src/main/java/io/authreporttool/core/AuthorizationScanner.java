package io.authreporttool.core;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpMethod;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.filter.OncePerRequestFilter;

import java.lang.reflect.Field;
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

    /**
     * Constructor to initialize the AuthorizationScanner with a ReflectionUtils instance.
     * @param reflectionUtils Utility class used for reflection-based operations.
     */
    public AuthorizationScanner(ReflectionUtils reflectionUtils) {
        this.reflectionUtils = reflectionUtils;
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
        if (method.isAnnotationPresent(GetMapping.class)) {
            return HttpMethod.GET.name();
        } else if (method.isAnnotationPresent(PostMapping.class)) {
            return HttpMethod.POST.name();
        } else if (method.isAnnotationPresent(PutMapping.class)) {
            return HttpMethod.PUT.name();
        } else if (method.isAnnotationPresent(DeleteMapping.class)) {
            return HttpMethod.DELETE.name();
        } else if (method.isAnnotationPresent(RequestMapping.class)) {
            RequestMapping mapping = method.getAnnotation(RequestMapping.class);
            return mapping.method().length > 0 ? mapping.method()[0].name() : HttpMethod.GET.name();
        }
        return HttpMethod.GET.name(); // Default to GET if not specified
    }

    /**
     * Scans the security configuration class to identify custom filters and API key authentication.
     * @param configClass The security configuration class to scan.
     * @param authInfoList The list of EndpointAuthInfo to update with additional security information.
     */
    private void scanSecurityConfig(Class<?> configClass, List<EndpointAuthInfo> authInfoList) {
        try {
            Object configInstance = configClass.getDeclaredConstructor().newInstance();

            for (Method method : configClass.getDeclaredMethods()) {
                if (SecurityFilterChain.class.isAssignableFrom(method.getReturnType())) {
                    method.setAccessible(true);
                    Object[] params = new Object[method.getParameterCount()];
                    SecurityFilterChain filterChain = (SecurityFilterChain) method.invoke(configInstance, params);
                    scanFilterChain(filterChain, authInfoList);
                }
            }
        } catch (Exception e) {
            logger.error("Error scanning security config: " + configClass.getName(), e);
        }
    }

    /**
     * Scans a SecurityFilterChain to identify custom filters that might implement API key authentication.
     * @param filterChain The SecurityFilterChain to scan.
     * @param authInfoList The list of EndpointAuthInfo to update with API key authentication information.
     */
    private void scanFilterChain(SecurityFilterChain filterChain, List<EndpointAuthInfo> authInfoList) {
        try {
            if (filterChain instanceof FilterChainProxy) {
                FilterChainProxy filterChainProxy = (FilterChainProxy) filterChain;
                List<SecurityFilterChain> chains = filterChainProxy.getFilterChains();

                for (SecurityFilterChain chain : chains) {
                    RequestMatcher matcher = getRequestMatcher(chain);
                    List<OncePerRequestFilter> filters = getFilters(chain);

                    for (OncePerRequestFilter filter : filters) {
                        String apiKeyHeaderName = detectApiKeyHeader(filter);
                        if (apiKeyHeaderName != null) {
                            updateAuthInfoWithApiKey(authInfoList, matcher, apiKeyHeaderName);
                        }
                    }
                }
            }
        } catch (Exception e) {
            logger.error("Error scanning filter chain", e);
        }
    }

    /**
     * Attempts to get the RequestMatcher from a SecurityFilterChain using reflection.
     * @param chain The SecurityFilterChain to examine.
     * @return The RequestMatcher for the chain, or null if it can't be retrieved.
     */
    private RequestMatcher getRequestMatcher(SecurityFilterChain chain) {
        try {
            Field requestMatcherField = findField(chain.getClass(), "requestMatcher");
            if (requestMatcherField != null) {
                requestMatcherField.setAccessible(true);
                return (RequestMatcher) requestMatcherField.get(chain);
            }
        } catch (Exception e) {
            logger.warn("Unable to get RequestMatcher from chain: " + chain, e);
        }
        return null;
    }

    /**
     * Attempts to get the list of filters from a SecurityFilterChain using reflection.
     * @param chain The SecurityFilterChain to examine.
     * @return A list of OncePerRequestFilter objects, or an empty list if they can't be retrieved.
     */
    private List<OncePerRequestFilter> getFilters(SecurityFilterChain chain) {
        try {
            Field filtersField = findField(chain.getClass(), "filters");
            if (filtersField != null) {
                filtersField.setAccessible(true);
                List<?> filters = (List<?>) filtersField.get(chain);
                List<OncePerRequestFilter> result = new ArrayList<>();
                for (Object filter : filters) {
                    if (filter instanceof OncePerRequestFilter) {
                        result.add((OncePerRequestFilter) filter);
                    }
                }
                return result;
            }
        } catch (Exception e) {
            logger.warn("Unable to get filters from chain: " + chain, e);
        }
        return new ArrayList<>();
    }

    /**
     * Finds a field in the class hierarchy of the given class.
     * @param clazz The class to search.
     * @param fieldName The name of the field to find.
     * @return The Field object if found, null otherwise.
     */
    private Field findField(Class<?> clazz, String fieldName) {
        Class<?> currentClass = clazz;
        while (currentClass != null) {
            try {
                return currentClass.getDeclaredField(fieldName);
            } catch (NoSuchFieldException e) {
                currentClass = currentClass.getSuperclass();
            }
        }
        return null;
    }

    /**
     * Checks if a filter is likely to be an API key authentication filter and extracts the header name.
     * @param filter The filter to check.
     * @return The API key header name if detected, null otherwise.
     */
    private String detectApiKeyHeader(OncePerRequestFilter filter) {
        String filterName = filter.getClass().getSimpleName().toLowerCase();
        if (filterName.contains("apikey") || filterName.contains("token") ||
                filterName.contains("auth") || filterName.contains("key")) {

            for (Field field : filter.getClass().getDeclaredFields()) {
                field.setAccessible(true);
                String fieldName = field.getName().toLowerCase();
                if (fieldName.contains("header") || fieldName.contains("key") || fieldName.contains("token")) {
                    try {
                        Object value = field.get(filter);
                        if (value instanceof String) {
                            return (String) value;
                        }
                    } catch (IllegalAccessException e) {
                        logger.warn("Unable to access field: " + field.getName(), e);
                    }
                }
            }

            return "X-API-Key"; // Default header name if not found
        }
        return null;
    }

    /**
     * Updates EndpointAuthInfo objects that match the given RequestMatcher with API key information.
     * @param authInfoList The list of EndpointAuthInfo objects to update.
     * @param matcher The RequestMatcher to use for identifying which endpoints to update.
     * @param apiKeyHeaderName The name of the API key header.
     */
    private void updateAuthInfoWithApiKey(List<EndpointAuthInfo> authInfoList, RequestMatcher matcher, String apiKeyHeaderName) {
        if (matcher == null) {
            return;
        }

        if (matcher instanceof AntPathRequestMatcher) {
            AntPathRequestMatcher antMatcher = (AntPathRequestMatcher) matcher;
            updateForAntMatcher(authInfoList, antMatcher, apiKeyHeaderName);
        } else {
            logger.warn("Unsupported RequestMatcher type: " + matcher.getClass().getName());
        }
    }

    /**
     * Updates EndpointAuthInfo objects that match the given AntPathRequestMatcher.
     * @param authInfoList The list of EndpointAuthInfo objects to update.
     * @param matcher The AntPathRequestMatcher to use for matching.
     * @param apiKeyHeaderName The name of the API key header.
     */
    private void updateForAntMatcher(List<EndpointAuthInfo> authInfoList, AntPathRequestMatcher matcher, String apiKeyHeaderName) {
        String pattern = matcher.getPattern();
        for (EndpointAuthInfo info : authInfoList) {
            if (info.getPath().startsWith(pattern) || pattern.equals("/**")) {
                info.setApiKeyRequired(true);
                info.setApiKeyHeaderName(apiKeyHeaderName);
                logger.info("API Key required for endpoint: " + info.getPath() + ", Header: " + apiKeyHeaderName);
            }
        }
    }
}