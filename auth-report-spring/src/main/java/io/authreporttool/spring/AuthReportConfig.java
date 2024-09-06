package io.authreporttool.spring;

import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReflectionUtils;
import io.authreporttool.core.ReportGenerator;
import io.authreporttool.core.SecurityConfigAnalyzer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AuthReportConfig {

    @Bean
    public ReflectionUtils reflectionUtils() {
        return new ReflectionUtils();
    }

    public SecurityConfigAnalyzer securityConfigAnalyzer() {
        return new SecurityConfigAnalyzer();
    }

    @Bean
    public AuthorizationScanner authorizationScanner(ReflectionUtils reflectionUtils) {
        return new AuthorizationScanner(reflectionUtils, securityConfigAnalyzer());
    }

    @Bean
    public ReportGenerator reportGenerator(AuthorizationScanner authorizationScanner) {
        return new ReportGenerator(authorizationScanner);
    }
}