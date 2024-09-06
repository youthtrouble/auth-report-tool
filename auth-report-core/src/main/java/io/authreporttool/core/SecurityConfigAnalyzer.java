package io.authreporttool.core;

import org.objectweb.asm.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.*;

public class SecurityConfigAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfigAnalyzer.class);

    private Map<String, FilterAnalysis> filterAnalyses = new HashMap<>();
    private boolean apiKeyFilterAdded = false;
    private boolean basicAuthEnabled = false;

    public void analyzeSecurityFilterChain(Method method, EndpointAuthInfo authInfo) {
        try {
            logger.info("Analyzing SecurityFilterChain method: {}", method.getName());
            String className = method.getDeclaringClass().getName();
            ClassReader reader = new ClassReader(className);
            SecurityConfigVisitor visitor = new SecurityConfigVisitor(method.getName());
            reader.accept(visitor, ClassReader.SKIP_DEBUG);

            interpretSecurityConfig(visitor.getConfigSteps(), authInfo);

            for (String filterClassName : visitor.getCustomFilters()) {
                analyzeCustomFilter(filterClassName);
            }

            updateAuthInfo(authInfo);

            logger.info("Security features detected: {}", authInfo.getSecurityFeatures());
        } catch (IOException e) {
            logger.error("Error analyzing SecurityFilterChain method", e);
        } catch (Exception e) {
            logger.error("Unexpected error during security configuration analysis", e);
        }
    }

    private void interpretSecurityConfig(List<SecurityConfigVisitor.SecurityConfigStep> steps, EndpointAuthInfo authInfo) {
        for (SecurityConfigVisitor.SecurityConfigStep step : steps) {
            if (step.name.equals("addFilterBefore") && step.descriptor.contains("ApiKeyAuthFilter")) {
                apiKeyFilterAdded = true;
                logger.info("API Key filter added to security chain");
            } else if (step.name.equals("httpBasic")) {
                basicAuthEnabled = true;
                logger.info("Basic Authentication enabled");
            } else if (step.name.equals("sessionManagement")) {
                authInfo.setSessionManagement("Custom");
                authInfo.addSecurityFeature("Custom Session Management");
            }
        }

        if (basicAuthEnabled) {
            authInfo.setBasicAuthRequired(true);
            authInfo.addSecurityFeature("Basic Authentication");
        }
    }

    private void updateAuthInfo(EndpointAuthInfo authInfo) {
        if (apiKeyFilterAdded) {
            for (FilterAnalysis filterAnalysis : filterAnalyses.values()) {
                if (filterAnalysis.getFilterName().contains("ApiKeyAuthFilter")) {
                    for (String endpoint : filterAnalysis.getApplicableEndpoints()) {
                        if (authInfo.getPath().equals(endpoint)) {
                            authInfo.setApiKeyRequired(true);
                            authInfo.addSecurityFeature("API Key Authentication required for " + endpoint);
                            logger.info("API Key required for endpoint: {}", endpoint);
                        }
                    }
                    if (filterAnalysis.getApplicableEndpoints().isEmpty()) {
                        authInfo.addSecurityFeature("API Key Authentication potentially required (check implementation)");
                    }
                }
            }
        }
    }

    private void analyzeCustomFilter(String filterClassName) {
        try {
            ClassReader reader = new ClassReader(filterClassName);
            CustomFilterVisitor visitor = new CustomFilterVisitor(filterClassName);
            reader.accept(visitor, ClassReader.SKIP_DEBUG);

            FilterAnalysis analysis = visitor.getFilterAnalysis();
            filterAnalyses.put(filterClassName, analysis);

            logger.info("Analyzed custom filter: {}", filterClassName);
            logger.info("Filter applies to: {}", analysis.getApplicableEndpoints());
        } catch (IOException e) {
            logger.error("Error analyzing custom filter: " + filterClassName, e);
        }
    }

    private static class SecurityConfigVisitor extends ClassVisitor {
        private final String targetMethodName;
        private boolean inTargetMethod = false;
        private List<SecurityConfigStep> configSteps = new ArrayList<>();
        private final List<String> customFilters = new ArrayList<>();

        public SecurityConfigVisitor(String targetMethodName) {
            super(Opcodes.ASM9);
            this.targetMethodName = targetMethodName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (name.equalsIgnoreCase(targetMethodName)) {
                inTargetMethod = true;
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                        if (inTargetMethod) {
                            configSteps.add(new SecurityConfigStep(owner, name, descriptor));
                            if (name.equals("addFilterBefore") || name.equals("addFilterAfter")) {
                                customFilters.add(extractFilterClassName(descriptor));
                            }
                        }
                        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (inTargetMethod && value instanceof String) {
                            configSteps.add(new SecurityConfigStep("LDC", value.toString(), null));
                        }
                        super.visitLdcInsn(value);
                    }
                };
            }
            return null;
        }

        @Override
        public void visitEnd() {
            inTargetMethod = false;
            super.visitEnd();
        }

        private String extractFilterClassName(String descriptor) {
            int start = descriptor.indexOf("L") + 1;
            int end = descriptor.indexOf(";");
            return descriptor.substring(start, end).replace("/", ".");
        }

        public List<SecurityConfigStep> getConfigSteps() {
            return configSteps;
        }

        public List<String> getCustomFilters() {
            return customFilters;
        }

        static class SecurityConfigStep {
            String owner;
            String name;
            String descriptor;

            SecurityConfigStep(String owner, String name, String descriptor) {
                this.owner = owner;
                this.name = name;
                this.descriptor = descriptor;
            }

            @Override
            public String toString() {
                return owner + "." + name + (descriptor != null ? descriptor : "");
            }
        }
    }

    private static class CustomFilterVisitor extends ClassVisitor {
        private final FilterAnalysis filterAnalysis;
        private boolean inDoFilterInternal = false;
        private boolean expectingEndpoint = false;
        private boolean foundRequestURICheck = false;
        private String lastStringConstant = null;

        public CustomFilterVisitor(String filterClassName) {
            super(Opcodes.ASM9);
            this.filterAnalysis = new FilterAnalysis(filterClassName);
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (name.equals("doFilterInternal")) {
                inDoFilterInternal = true;
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                        if (name.equals("getRequestURI")) {
                            foundRequestURICheck = true;
                        } else if (name.equals("equals") && foundRequestURICheck && lastStringConstant != null) {
                            filterAnalysis.addApplicableEndpoint(lastStringConstant);
                            logger.info("Found applicable endpoint for filter {}: {}", filterAnalysis.getFilterName(), lastStringConstant);
                            foundRequestURICheck = false;
                            lastStringConstant = null;
                        }
                        super.visitMethodInsn(opcode, owner, name, descriptor, isInterface);
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            lastStringConstant = (String) value;
                        }
                        super.visitLdcInsn(value);
                    }
                };
            }
            return null;
        }

        @Override
        public void visitEnd() {
            inDoFilterInternal = false;
            super.visitEnd();
        }

        public FilterAnalysis getFilterAnalysis() {
            return filterAnalysis;
        }
    }

    private static class FilterAnalysis {
        private final String filterName;
        private final Set<String> applicableEndpoints = new HashSet<>();

        public FilterAnalysis(String filterClassName) {
            this.filterName = filterClassName.substring(filterClassName.lastIndexOf('.') + 1);
        }

        public void addApplicableEndpoint(String endpoint) {
            applicableEndpoints.add(endpoint);
        }

        public String getFilterName() {
            return filterName;
        }

        public Set<String> getApplicableEndpoints() {
            return applicableEndpoints;
        }
    }
}