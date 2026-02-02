# Decompiler App

## Overview

The **Decompiler** app is a Django application designed to capture and analyze user data from browser extensions. It focuses on modern browser extension technologies including:

- **Java Applets** (.jar, .class files)
- **Flash/ActionScript** (.swf files)
- **Silverlight** (.xap packages)
- **JavaScript** browser extensions

## Features

### 1. Extension Package Management
- Upload and capture browser extension packages
- Detect extension type automatically
- Calculate and store file checksums
- Track download sources and metadata

### 2. Decompilation Workflow
- Download browser extension bytecode or packages
- Select appropriate decompiler based on extension type
- Decompile bytecode to source code
- Track job status and progress
- Store and retrieve decompiled source

### 3. Obfuscation Detection and Defeat
- Detect common obfuscation techniques:
  - Name mangling/renaming
  - String encryption
  - Control flow obfuscation
  - Dead code injection
  - Opaque predicates
  - Reflection-based obfuscation
- Attempt automatic deobfuscation
- Track confidence scores and evidence

### 4. Source Code Analysis
- Extract API endpoints and network requests
- Analyze data flows
- Identify security vulnerabilities
- Find JavaScript injection points
- Map application logic

### 5. Traffic Interception
- Capture browser extension traffic
- Parse different protocols (HTTP, AMF, Java serialization)
- Deserialize captured data
- Enable traffic replay and modification

### 6. Recompilation and Execution
- Recompile modified source code
- Execute inside browser environment
- Execute in standalone environment
- Monitor execution results

### 7. JavaScript Manipulation
- Inject JavaScript hooks into extensions
- Manipulate extension components
- Intercept and modify extension behavior

### 8. Web Application Interaction
- Programmatically interact with target web apps
- Extract authentication mechanisms
- Generate API clients from analysis
- Automate interactions

## Architecture

### Models

- **ExtensionPackage**: Stores captured extension packages with metadata
- **DecompilationJob**: Tracks decompilation jobs and results
- **ObfuscationTechnique**: Catalogs obfuscation techniques
- **DetectedObfuscation**: Links jobs to detected obfuscation
- **ExtensionAnalysis**: Stores analysis results
- **TrafficInterception**: Captures intercepted traffic

### Views

The app provides REST API endpoints for:
- Package upload and management
- Job creation and status tracking
- Analysis execution and results
- Obfuscation detection
- Traffic capture and replay
- Web app interaction

### Engine Components

- **DecompilationEngine**: Core decompilation logic
- **ObfuscationDetector**: Detects obfuscation patterns
- **CodeAnalyzer**: Analyzes decompiled source
- **TrafficAnalyzer**: Parses intercepted traffic
- **RecompilationEngine**: Recompiles modified code

## Supported Decompilers

### Java Applets
- **JAD**: Classic Java decompiler
- **CFR**: Modern, handles Java 8+
- **Procyon**: Good for newer Java features
- **Krakatau**: Python-based, very accurate

### Flash/ActionScript
- **JPEXS Free Flash Decompiler**: Best open-source option
- **SWFTools**: Command-line utilities
- **RABCDASM**: Low-level ABC bytecode tools

### Silverlight
- **ILSpy**: Open-source .NET decompiler
- **dotPeek**: JetBrains' free decompiler
- **dnSpy**: Debugger and decompiler

## Traffic Interception Obstacles and Solutions

### Obstacles

1. **HTTPS Encryption**: Extensions use encrypted connections
2. **Certificate Pinning**: Extensions may validate specific certificates
3. **WebSocket Encryption**: Real-time encrypted communication
4. **Custom Binary Protocols**: Proprietary serialization formats
5. **Anti-debugging**: Detection and prevention of analysis

### Solutions

1. **Use mitmproxy or similar** for HTTP/HTTPS interception
2. **Certificate trust injection** to bypass pinning
3. **Protocol-aware interception** for WebSockets
4. **Custom parsers** for AMF, Java serialization, etc.
5. **Code modification** to defeat anti-debugging

## Usage

### Starting the Development Server

```bash
python manage.py runserver
```

Visit `http://localhost:8000/decompiler/` to access the home page.

### Uploading an Extension Package

```bash
curl -X POST http://localhost:8000/decompiler/packages/upload/ \
  -F "file=@extension.jar" \
  -F "name=MyExtension" \
  -F "download_url=https://example.com/extension.jar"
```

### Starting a Decompilation Job

```bash
curl -X POST http://localhost:8000/decompiler/jobs/start/ \
  -H "Content-Type: application/json" \
  -d '{
    "package_id": "uuid-here",
    "decompiler_tool": "CFR"
  }'
```

### Analyzing Code

```bash
curl -X POST http://localhost:8000/decompiler/analyze/ \
  -H "Content-Type: application/json" \
  -d '{
    "job_id": "uuid-here"
  }'
```

## Development Status

⚠️ **This app is currently scaffolded with stub implementations.**

All features are outlined with:
- Detailed docstrings explaining responsibilities
- Method signatures with expected parameters and return values
- TODOs marking implementation tasks
- Comments describing algorithms and approaches

This makes it easy for developers to understand the intended functionality and implement the actual logic.

## Implementation TODOs

### High Priority
- [ ] Implement file upload handling in views
- [ ] Integrate actual decompiler tools in engine
- [ ] Add obfuscation detection algorithms
- [ ] Create static analysis engine
- [ ] Implement traffic capture with mitmproxy

### Medium Priority
- [ ] Build web-based source code viewer
- [ ] Add syntax highlighting
- [ ] Implement protocol parsers (AMF, Java serialization)
- [ ] Create recompilation pipelines
- [ ] Add JavaScript injection framework

### Low Priority
- [ ] Machine learning-based obfuscation detection
- [ ] Advanced control flow analysis
- [ ] Automated vulnerability scanning
- [ ] Integration with CVE databases
- [ ] Real-time traffic monitoring

## Testing

Run tests with:

```bash
python manage.py test decompiler
```

Currently, tests are scaffolded with TODOs for implementation.

## Admin Interface

Access the Django admin at `http://localhost:8000/admin/` to manage:
- Extension packages
- Decompilation jobs
- Obfuscation techniques
- Analysis results
- Intercepted traffic

## API Documentation

All endpoints currently return:
```json
{
  "error": "Not implemented",
  "message": "Feature is not yet implemented"
}
```

This allows the API structure to be validated and tested before implementation.

## Contributing

When implementing features:
1. Read the docstrings and TODOs carefully
2. Maintain the existing architecture
3. Add comprehensive tests
4. Update this README with implementation notes
5. Document any external dependencies (decompiler tools, etc.)

## Security Considerations

This app is designed for **security research and testing purposes only**. Users must:
- Obtain proper authorization before analyzing extensions
- Comply with applicable laws and regulations
- Use responsibly and ethically
- Not use for malicious purposes

## License

See the main project LICENSE file.
