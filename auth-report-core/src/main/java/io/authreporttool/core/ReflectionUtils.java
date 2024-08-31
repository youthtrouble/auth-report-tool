package io.authreporttool.core;

import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

import java.io.File;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.net.URL;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;
import java.util.stream.Collectors;

public class ReflectionUtils {

    private static final Logger logger = LoggerFactory.getLogger(AuthorizationScanner.class);

    /**
     * Finds all classes in the specified base package that are annotated with the given annotation.
     * @param basePackage The package to scan.
     * @param annotation The annotation class to look for.
     * @return A set of classes annotated with the specified annotation, or an empty set if the package is inaccessible or doesn't exist.
     */
    public Set<Class<?>> findAnnotatedClasses(String basePackage, Class<? extends Annotation> annotation) {
        logger.info("Attempting to scan package: {} for annotation: {}", basePackage, annotation.getSimpleName());

        // Step 1: Check if the package exists
        String packagePath = basePackage.replace('.', '/');
        URL resourceUrl = getClass().getClassLoader().getResource(packagePath);
        if (resourceUrl == null) {
            logger.error("Package {} does not exist in the classpath", basePackage);
            return Collections.emptySet();
        }

        // Step 2: List contents of the package
        File packageDir = new File(resourceUrl.getFile());
        if (packageDir.exists() && packageDir.isDirectory()) {
            logger.info("Contents of package {}:", basePackage);
            listDirectoryContents(packageDir, "");
        } else {
            logger.warn("Package directory does not exist or is not a directory: {}", packageDir.getAbsolutePath());
        }

        // Step 3: Get URLs for the package
        Set<URL> urls = new HashSet<>(ClasspathHelper.forPackage(basePackage));
        logger.info("URLs found for package {}: {}", basePackage, urls);

        if (urls.isEmpty()) {
            logger.warn("No URLs found for package: {}. The package might not exist or is inaccessible.", basePackage);
            return Collections.emptySet();
        }

        // Step 4: Perform the scan
        try {
            Reflections reflections = new Reflections(new ConfigurationBuilder()
                    .setUrls(urls)
                    .setScanners(new SubTypesScanner(false), new TypeAnnotationsScanner()));

            Set<Class<?>> annotatedClasses = new HashSet<>(reflections.getTypesAnnotatedWith(annotation));

            logger.info("Found {} classes annotated with {} in package {}",
                    annotatedClasses.size(), annotation.getSimpleName(), basePackage);

            // Step 5: Log found classes
            for (Class<?> clazz : annotatedClasses) {
                logger.info("Found annotated class: {}", clazz.getName());
            }

            return annotatedClasses;
        } catch (Exception e) {
            logger.error("Error occurred while scanning package: " + basePackage, e);
            return Collections.emptySet();
        }
    }

    private void listDirectoryContents(File dir, String indent) {
        File[] files = dir.listFiles();
        if (files != null) {
            for (File file : files) {
                logger.info("{}{}", indent, file.getName());
                if (file.isDirectory()) {
                    listDirectoryContents(file, indent + "  ");
                }
            }
        }
    }


    /**
     * Finds all classes in the specified base package that have methods returning SecurityFilterChain.
     * This is useful for identifying security configuration classes.
     * @param basePackage The package to scan.
     * @return A set of classes that have methods returning SecurityFilterChain.
     */
    public Set<Class<?>> findClassesWithSecurityFilterChainMethods(String basePackage) {
        Reflections reflections = new Reflections(new ConfigurationBuilder()
                .setUrls(ClasspathHelper.forPackage(basePackage))
                .setScanners(new SubTypesScanner(false), new MethodAnnotationsScanner()));

        Set<Method> methods = reflections.getMethodsReturn(SecurityFilterChain.class);
        return methods.stream()
                .map(Method::getDeclaringClass)
                .collect(Collectors.toSet());
    }

    /**
     * Finds all classes in the specified base package that have methods annotated with @Bean
     * and return the specified type.
     * This is useful for identifying configuration classes in Spring applications that define
     * specific types of beans.
     *
     * @param basePackage The package to scan.
     * @param returnType The return type of the bean methods to look for.
     * @return A set of classes that have methods annotated with @Bean and returning the specified type.
     */
    public Set<Class<?>> findClassesWithBeanMethods(String basePackage, Class<?> returnType) {
        Reflections reflections = new Reflections(new ConfigurationBuilder()
                .setUrls(ClasspathHelper.forPackage(basePackage))
                .setScanners(new SubTypesScanner(false), new MethodAnnotationsScanner()));

        Set<Method> beanMethods = reflections.getMethodsAnnotatedWith(Bean.class);
        return beanMethods.stream()
                .filter(method -> method.getReturnType().equals(returnType))
                .map(Method::getDeclaringClass)
                .collect(Collectors.toSet());
    }
}