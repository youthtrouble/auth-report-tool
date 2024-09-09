package io.authreporttool.spring;

import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReflectionUtils;
import io.authreporttool.core.ReportGenerator;
import io.authreporttool.core.SecurityConfigAnalyzer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * AuthReportConfig is a Spring Configuration class that defines beans for the
 * Authorization Report tool. It sets up the necessary components for scanning,
 * analyzing, and generating authorization reports within a Spring application context.
 */
@Configuration
public class AuthReportConfig {

    /**
     * Creates and configures a ReflectionUtils bean.
     * ReflectionUtils is used for reflection-based operations in the authorization scanning process.
     *
     * @return A new instance of ReflectionUtils.
     */
    @Bean
    public ReflectionUtils reflectionUtils() {
        return new ReflectionUtils();
    }

    /**
     * Creates and configures a SecurityConfigAnalyzer.
     * SecurityConfigAnalyzer is responsible for analyzing Spring Security configurations.
     *
     * Note: This method is not annotated with @Bean, which means it won't be managed by Spring.
     * Consider adding @Bean annotation if you want this to be a Spring-managed bean.
     *
     * @return A new instance of SecurityConfigAnalyzer.
     */
    @Bean
    public SecurityConfigAnalyzer securityConfigAnalyzer() {
        return new SecurityConfigAnalyzer();
    }

    /**
     * Creates and configures an AuthorizationScanner bean.
     * AuthorizationScanner is the core component responsible for scanning the application
     * for authorization configurations.
     *
     * @param reflectionUtils The ReflectionUtils bean to be used by the scanner.
     * @return A new instance of AuthorizationScanner.
     */
    @Bean
    public AuthorizationScanner authorizationScanner(ReflectionUtils reflectionUtils) {
        return new AuthorizationScanner(reflectionUtils, securityConfigAnalyzer());
    }

    /**
     * Creates and configures a ReportGenerator bean.
     * ReportGenerator is responsible for generating authorization reports based on
     * the data collected by the AuthorizationScanner.
     *
     * @param authorizationScanner The AuthorizationScanner bean to be used by the generator.
     * @return A new instance of ReportGenerator.
     */
    @Bean
    public ReportGenerator reportGenerator(AuthorizationScanner authorizationScanner) {
        return new ReportGenerator(authorizationScanner);
    }
}