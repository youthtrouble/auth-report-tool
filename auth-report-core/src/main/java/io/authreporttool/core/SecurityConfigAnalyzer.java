package io.authreporttool.core;

import org.objectweb.asm.ClassReader;
import org.objectweb.asm.ClassVisitor;
import org.objectweb.asm.MethodVisitor;
import org.objectweb.asm.Opcodes;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.lang.reflect.Method;
import java.util.HashSet;
import java.util.Set;

public class SecurityConfigAnalyzer {
    private static final Logger logger = LoggerFactory.getLogger(SecurityConfigAnalyzer.class);

    public void analyzeSecurityFilterChain(Method method, EndpointAuthInfo authInfo) {
        try {
            logger.info("Analyzing SecurityFilterChain method: {}", method.getName());
            String className = method.getDeclaringClass().getName();
            ClassReader reader = new ClassReader(className);
            SecurityConfigVisitor visitor = new SecurityConfigVisitor(method.getName());
            reader.accept(visitor, ClassReader.SKIP_DEBUG);

            updateAuthInfo(authInfo, visitor);

            logger.info("Security features detected: {}", authInfo.getSecurityFeatures());
        } catch (IOException e) {
            logger.error("Error analyzing SecurityFilterChain method", e);
        } catch (Exception e) {
            logger.error("Unexpected error during security configuration analysis", e);
        }
    }

    private void updateAuthInfo(EndpointAuthInfo authInfo, SecurityConfigVisitor visitor) {
        authInfo.setApiKeyRequired(visitor.isApiKeyAuthDetected());
        authInfo.setBasicAuthRequired(visitor.isBasicAuthRequired());

        if (visitor.getSessionManagement() != null) {
            authInfo.setSessionManagement(visitor.getSessionManagement());
        }

        for (String feature : visitor.getSecurityFeatures()) {
            authInfo.addSecurityFeature(feature);
        }
    }

    private static class SecurityConfigVisitor extends ClassVisitor {
        private final String targetMethodName;
        private boolean apiKeyAuthDetected = false;
        private boolean basicAuthDetected = false;
        private boolean csrfDisabled = false;
        private String sessionManagement = null;
        private final Set<String> securityFeatures = new HashSet<>();

        public SecurityConfigVisitor(String targetMethodName) {
            super(Opcodes.ASM9);
            this.targetMethodName = targetMethodName;
        }

        @Override
        public MethodVisitor visitMethod(int access, String name, String descriptor, String signature, String[] exceptions) {
            if (name.equalsIgnoreCase(targetMethodName)) {
                return new MethodVisitor(Opcodes.ASM9) {
                    @Override
                    public void visitMethodInsn(int opcode, String owner, String name, String descriptor, boolean isInterface) {
                        analyzeMethodCall(owner, name, descriptor);
                    }

                    @Override
                    public void visitLdcInsn(Object value) {
                        if (value instanceof String) {
                            String stringValue = (String) value;
                            if (stringValue.contains("SessionCreationPolicy")) {
                                sessionManagement = determineSessionManagement(stringValue);
                                logger.info("Detected Session Management: {}", sessionManagement);
                            }
                        }
                    }
                };
            }
            return null;
        }

        private void analyzeMethodCall(String owner, String name, String descriptor) {
            logger.debug("Analyzing method call: {}.{}{}", owner, name, descriptor);

            if (isApiKeyRelatedCall(owner, name, descriptor)) {
                apiKeyAuthDetected = true;
                securityFeatures.add("API Key Authentication");
                logger.info("Detected API Key Authentication");
            }

            if (isSessionManagementRelatedCall(owner, name, descriptor)) {
                if (sessionManagement == null) {
                    sessionManagement = "DEFAULT";
                }
                securityFeatures.add("Session Management: " + sessionManagement);
                logger.info("Detected Session Management call");
            }

            if (isBasicAuthRelatedCall(owner, name)) {
                basicAuthDetected = true;
                securityFeatures.add("Basic Authentication");
                logger.info("Detected Basic Authentication");
            }

            if (isJwtRelatedCall(owner, name)) {
                securityFeatures.add("JWT Authentication");
                logger.info("Detected JWT Authentication");
            }

            if (isOAuth2RelatedCall(owner, name)) {
                securityFeatures.add("OAuth2 Authentication");
                logger.info("Detected OAuth2 Authentication");
            }

            if (isCsrfRelatedCall(owner, name, descriptor)) {
                csrfDisabled = true;
                securityFeatures.add("CSRF Disabled");
                logger.info("Detected CSRF Disabled");
            }
        }

        private boolean isApiKeyRelatedCall(String owner, String name, String descriptor) {
            boolean isApiKeyClass = owner.toLowerCase().contains("apikey") || owner.toLowerCase().contains("tokenauth");
            boolean isApiKeyMethod = name.toLowerCase().contains("apikey") || name.toLowerCase().contains("tokenauth");
            boolean isAddFilterMethod = name.toLowerCase().contains("addfilter");

            if (isApiKeyClass || isApiKeyMethod || (isAddFilterMethod && descriptor.contains("ApiKeyAuthFilter"))) {
                logger.info("Detected API Key related call: {}.{}{}", owner, name, descriptor);
                return true;
            }
            return false;
        }

        private boolean isBasicAuthRelatedCall(String owner, String name) {
            return owner.toLowerCase().contains("httpsecurity") && name.equalsIgnoreCase("httpBasic");
        }

        private boolean isSessionManagementRelatedCall(String owner, String name, String descriptor) {
            return owner.toLowerCase().contains("httpsecurity") &&
                    name.toLowerCase().contains("sessionmanagement");
        }

        private boolean isJwtRelatedCall(String owner, String name) {
            return owner.toLowerCase().contains("jwt") &&
                    (name.toLowerCase().contains("configure") || name.toLowerCase().contains("addfilter"));
        }

        private boolean isOAuth2RelatedCall(String owner, String name) {
            return owner.toLowerCase().contains("oauth2") &&
                    (name.toLowerCase().contains("configure") || name.toLowerCase().contains("addfilter"));
        }

        private boolean isCsrfRelatedCall(String owner, String name, String descriptor) {
            return owner.toLowerCase().contains("httpsecurity") &&
                    name.toLowerCase().contains("csrf") &&
                    descriptor.toLowerCase().contains("disable");
        }

        private String determineSessionManagement(String descriptor) {
            if (descriptor.contains("ALWAYS")) return "ALWAYS";
            if (descriptor.contains("NEVER")) return "NEVER";
            if (descriptor.contains("IF_REQUIRED")) return "IF_REQUIRED";
            if (descriptor.contains("STATELESS")) return "STATELESS";
            return "DEFAULT";
        }

        // Getters
        public boolean isApiKeyAuthDetected() { return apiKeyAuthDetected; }
        public boolean isBasicAuthRequired() { return basicAuthDetected; }
        public String getSessionManagement() { return sessionManagement; }
        public Set<String> getSecurityFeatures() { return securityFeatures; }
    }
}