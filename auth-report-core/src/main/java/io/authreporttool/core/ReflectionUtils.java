package io.authreporttool.core;

import org.reflections.Reflections;
import org.reflections.scanners.SubTypesScanner;
import org.reflections.util.ClasspathHelper;
import org.reflections.util.ConfigurationBuilder;

import java.lang.annotation.Annotation;
import java.util.Set;

public class ReflectionUtils {
    /**
     * Finds all classes in the specified base package that are annotated with the given annotation.
     * @param basePackage The package to scan.
     * @param annotation The annotation class to look for.
     * @return A set of classes annotated with the specified annotation.
     */
    public Set<Class<?>> findAnnotatedClasses(String basePackage, Class<?> annotation) {
        Reflections reflections = new Reflections(new ConfigurationBuilder()
                .setUrls(ClasspathHelper.forPackage(basePackage))
                .setScanners(new SubTypesScanner(false)));

        return reflections.getTypesAnnotatedWith((Class<? extends Annotation>) annotation);
    }
}
