# Authorization Report Tool

## Table of Contents

1. [Introduction](#introduction)
2. [Features](#features)
3. [Requirements](#requirements)
4. [Installation](#installation)
5. [Usage](#usage)
    - [Command Line Interface](#command-line-interface)
    - [Integrating with Spring Projects](#integrating-with-spring-projects)
6. [Configuration](#configuration)
7. [Output Format](#output-format)
8. [Advanced Usage](#advanced-usage)
9. [Troubleshooting](#troubleshooting)
10. [Contributing](#contributing)
11. [License](#license)

## Introduction

The Authorization Report Tool is a utility designed to analyze Spring Boot applications and generate comprehensive reports on the authorization and authentication mechanisms in place. It scans your codebase to identify endpoints, their associated HTTP methods, and the security constraints applied to them, including role-based access control and API key authentication.

## Features

- Scans Spring Boot applications for REST endpoints
- Identifies HTTP methods for each endpoint
- Detects role-based access control using `@PreAuthorize` annotations
- Recognizes API key authentication mechanisms
- Generates detailed reports in various formats (JSON, CSV, HTML)
- Command-line interface for easy integration into CI/CD pipelines
- Can be used as a library in other Java applications

## Requirements

- Java 11 or higher
- Spring Boot 2.x or 3.x
- Maven or Gradle (for building and running)

## Installation

### Using as a standalone tool

1. Clone the repository:
    
```bash
git clone https://github.com/youthtrouble/auth-report-tool.git
```
2. Build the project using Maven:

```bash
cd auth-report-tool
mvn clean package
```
3. The compiled JAR will be in the `target` directory.

### Adding as a dependency in your project

#### Maven

Add the following to your `pom.xml`:

```xml
<dependency>
 <groupId>io.authreporttool</groupId>
 <artifactId>auth-report-tool</artifactId>
 <version>1.0.0</version>
</dependency>
```

#### Gradle
Add the following to your build.gradle:
groovyCopyimplementation 'io.authreporttool:auth-report-tool:1.0.0'

### Usage
#### Command Line Interface
To run the tool from the command line:

``` bash
java -jar auth-report-tool.jar -p com.example.myproject -o report.json
```

Options:

```-p, --package```: The base package to scan (required)<br />
```-o, --output```: The output file path (optional, default: console output)<br />
```-f, --format```: Output format (json, csv, html) (optional, default: json)<br />
```-v, --verbose```: Enable verbose output<br />

#### Integrating with Spring Projects
To use the tool programmatically in your Spring project:
```java
import io.authreporttool.core.AuthorizationScanner;
import io.authreporttool.core.ReportGenerator;

@Service
public class SecurityAuditService {

    private final AuthorizationScanner scanner;
    private final ReportGenerator generator;

    @Autowired
    public SecurityAuditService(AuthorizationScanner scanner, ReportGenerator generator) {
        this.scanner = scanner;
        this.generator = generator;
    }

    public void generateSecurityReport() {
        List<EndpointAuthInfo> authInfo = scanner.scanApi("com.example.myproject");
        String report = generator.generateReport(authInfo, ReportFormat.JSON);
        // Process or save the report as needed
    }
}
```

### Configuration
The tool can be configured using a config.properties file in the classpath:

```properties
# Exclude packages from scanning
scanner.exclude.packages=com.example.test,com.example.dev

# Custom API key header names to look for
scanner.apikey.headers=X-API-Key,Custom-Auth-Key

# Minimum role level to include in the report (ROLE_USER, ROLE_ADMIN, etc.)
report.min.role.level=ROLE_USER
```

### Output Format

The tool generates reports in JSON, CSV, and HTML formats.

#### JSON
```json
{
  "endpoints": [
    {
      "path": "/api/v1/users",
      "methods": ["GET", "POST"],
      "roles": ["ROLE_USER", "ROLE_ADMIN"],
      "apikey": false
    },
    {
      "path": "/api/v1/products",
      "methods": ["GET"],
      "roles": ["ROLE_USER"],
      "apikey": true
    }
  ]
}
```

#### CSV
```csv
Path,Method,AuthExpression,ApiKeyRequired,ApiKeyHeaderName
/api/users,GET,hasRole('ADMIN'),false,
/api/products,POST,hasAnyRole('ADMIN', 'MANAGER'),true,X-API-Key
```

#### HTML

The tool generates an interactive HTML report with sortable and filterable tables.

### Advanced Usage

Example Jenkins pipeline step:
```groovy
stage('Security Audit') {
   steps {
      sh 'java -jar auth-report-tool.jar -p com.example.myproject -o security-report.json'
      archiveArtifacts artifacts: 'security-report.json', fingerprint: true
   }
}
```

### Troubleshooting

- Issue: Tool doesn't detect some endpoints
Solution: Ensure that your controllers are properly annotated with @RestController or @Controller

- Issue: API key authentication not detected
Solution: Check if your custom API key filter extends OncePerRequestFilter and contains fields with names like "header", "key", or "token"

If you encounter any issues beyond these or have questions, please open an issue on the GitHub repository.

### Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes.

### License

This project is licensed under the MIT License - see the LICENSE file for details.
