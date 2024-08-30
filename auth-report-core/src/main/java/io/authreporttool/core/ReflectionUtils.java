package io.authreporttool.core;

import org.reflections.Reflections;
import org.reflections.scanners.MethodAnnotationsScanner;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.scanners.TypeAnnotationsScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.SecurityFilterChain;

import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.util.Set;
import java.util.stream.Collectors;

public class ReflectionUtils {
    /**
     * Finds all classes in the specified base package that are annotated with the given annotation.
     * @param basePackage The package to scan.
     * @param annotation The annotation class to look for.
     * @return A set of classes annotated with the specified annotation.
     */
    public Set<Class<?>> findAnnotatedClasses(String basePackage, Class<? extends Annotation> annotation) {
        Reflections reflections = new Reflections(new ConfigurationBuilder()
                .setUrls(ClasspathHelper.forPackage(basePackage))
                .setScanners(new SubTypesScanner(false), new TypeAnnotationsScanner()));

        return reflections.getTypesAnnotatedWith(annotation);
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