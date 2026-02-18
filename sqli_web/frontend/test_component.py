#!/usr/bin/env python3
"""
Validation script for NoSQLAttackerGUI Component
Checks component structure, syntax, and configuration
"""
import os
import sys
import json
import re

def test_component_exists():
    """Test that component file exists"""
    print("Testing component file existence...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    if not os.path.exists(component_path):
        print(f"✗ Component file not found: {component_path}")
        return False
    
    file_size = os.path.getsize(component_path)
    print(f"✓ Component file exists ({file_size} bytes)")
    return True

def test_component_structure():
    """Test component has proper structure"""
    print("\nTesting component structure...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    with open(component_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for required imports
    required_imports = [
        "import React",
        "useState",
        "useEffect",
    ]
    
    for imp in required_imports:
        if imp not in content:
            print(f"✗ Missing required import: {imp}")
            return False
        print(f"✓ Found import: {imp}")
    
    # Check for type definitions
    type_definitions = [
        "type InjectionType",
        "interface Payload",
        "interface AttackResponse",
    ]
    
    for typedef in type_definitions:
        if typedef not in content:
            print(f"✗ Missing type definition: {typedef}")
            return False
        print(f"✓ Found type definition: {typedef}")
    
    # Check for component export
    if "export default" not in content:
        print("✗ Missing default export")
        return False
    print("✓ Component has default export")
    
    # Check for payload libraries
    if "PAYLOAD_LIBRARIES" not in content:
        print("✗ Missing PAYLOAD_LIBRARIES constant")
        return False
    print("✓ Found PAYLOAD_LIBRARIES constant")
    
    return True

def test_payload_completeness():
    """Test that all injection types have payloads"""
    print("\nTesting payload completeness...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    with open(component_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    injection_types = ['SQL', 'NoSQL', 'XPath', 'LDAP']
    
    for inj_type in injection_types:
        pattern = f"{inj_type}: \\["
        if not re.search(pattern, content):
            print(f"✗ Missing payloads for {inj_type}")
            return False
        
        # Count payload objects for this type
        section_match = re.search(f"{inj_type}: \\[(.*?)\\],", content, re.DOTALL)
        if section_match:
            section = section_match.group(1)
            payload_count = section.count("name:")
            if payload_count < 5:
                print(f"✗ Too few payloads for {inj_type}: {payload_count}")
                return False
            print(f"✓ Found {payload_count} payloads for {inj_type}")
        else:
            print(f"✗ Could not parse payloads for {inj_type}")
            return False
    
    return True

def test_documentation():
    """Test that documentation files exist"""
    print("\nTesting documentation...")
    
    doc_files = [
        "sqli_web/frontend/components/README.md",
        "sqli_web/frontend/components/VISUAL_GUIDE.md",
        "sqli_web/frontend/INTEGRATION_GUIDE.md",
    ]
    
    for doc_file in doc_files:
        if not os.path.exists(doc_file):
            print(f"✗ Missing documentation: {doc_file}")
            return False
        
        size = os.path.getsize(doc_file)
        if size < 1000:  # At least 1KB
            print(f"✗ Documentation too short: {doc_file} ({size} bytes)")
            return False
        
        print(f"✓ Found documentation: {doc_file} ({size} bytes)")
    
    return True

def test_configuration_files():
    """Test that configuration files are properly set up"""
    print("\nTesting configuration files...")
    
    # Test package.json
    if not os.path.exists("package.json"):
        print("✗ Missing package.json")
        return False
    
    with open("package.json", 'r') as f:
        package = json.load(f)
    
    # Check for React dependencies
    required_deps = ["react", "react-dom"]
    dependencies = package.get("dependencies", {})
    
    for dep in required_deps:
        if dep not in dependencies:
            print(f"✗ Missing dependency in package.json: {dep}")
            return False
        print(f"✓ Found dependency: {dep}")
    
    # Check for build scripts
    scripts = package.get("scripts", {})
    if "build:tsx" not in scripts:
        print("✗ Missing build:tsx script in package.json")
        return False
    print("✓ Found build:tsx script")
    
    # Test webpack config
    if not os.path.exists("webpack.config.js"):
        print("✗ Missing webpack.config.js")
        return False
    print("✓ Found webpack.config.js")
    
    # Test TypeScript config
    tsconfig_path = "sqli_web/frontend/tsconfig.json"
    if not os.path.exists(tsconfig_path):
        print(f"✗ Missing {tsconfig_path}")
        return False
    print(f"✓ Found {tsconfig_path}")
    
    # Test Tailwind config includes frontend
    if os.path.exists("tailwind.config.js"):
        with open("tailwind.config.js", 'r') as f:
            tailwind_content = f.read()
        
        if "sqli_web/frontend" not in tailwind_content:
            print("✗ Tailwind config doesn't include frontend directory")
            return False
        print("✓ Tailwind config includes frontend directory")
    
    return True

def test_component_features():
    """Test that all required features are present"""
    print("\nTesting component features...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    with open(component_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    features = [
        ("Tab selector", ["activeTab", "setActiveTab"]),
        ("Payload selection", ["selectedPayload", "handlePayloadSelect"]),
        ("Custom payload editor", ["customPayload", "setCustomPayload"]),
        ("Auto-fill functionality", ["handleAutoFill"]),
        ("Execute attack", ["handleExecute"]),
        ("Response logging", ["responseLog", "setResponseLog"]),
        ("Dark mode toggle", ["isDarkMode", "setIsDarkMode"]),
        ("Copy to clipboard", ["handleCopy", "clipboard"]),
    ]
    
    for feature_name, keywords in features:
        found = all(keyword in content for keyword in keywords)
        if not found:
            missing = [kw for kw in keywords if kw not in content]
            print(f"✗ Missing feature: {feature_name} (missing: {', '.join(missing)})")
            return False
        print(f"✓ Found feature: {feature_name}")
    
    return True

def test_styling():
    """Test that Tailwind CSS classes are used"""
    print("\nTesting styling...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    with open(component_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Check for Tailwind classes
    tailwind_patterns = [
        "className=",
        "bg-gradient-to-r",
        "dark:",
        "hover:",
        "rounded-",
        "shadow-",
    ]
    
    for pattern in tailwind_patterns:
        if pattern not in content:
            print(f"✗ Missing Tailwind pattern: {pattern}")
            return False
        print(f"✓ Found Tailwind pattern: {pattern}")
    
    # Check for Megido-specific classes
    megido_classes = [
        "glass-strong",
        "primary-500",
        "shadow-premium",
    ]
    
    for cls in megido_classes:
        if cls not in content:
            print(f"⚠ Missing Megido-specific class: {cls} (optional)")
        else:
            print(f"✓ Found Megido class: {cls}")
    
    return True

def test_jsdoc_comments():
    """Test that JSDoc comments are present"""
    print("\nTesting JSDoc documentation...")
    component_path = "sqli_web/frontend/components/NoSQLAttackerGUI.tsx"
    
    with open(component_path, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Count JSDoc blocks
    jsdoc_count = content.count("/**")
    
    if jsdoc_count < 10:
        print(f"✗ Insufficient JSDoc comments: {jsdoc_count} (expected at least 10)")
        return False
    
    print(f"✓ Found {jsdoc_count} JSDoc comment blocks")
    
    # Check for module documentation
    if "@module" not in content:
        print("⚠ Missing @module tag (optional)")
    else:
        print("✓ Found @module tag")
    
    return True

def main():
    """Run all validation tests"""
    print("=" * 60)
    print("NoSQLAttackerGUI Component - Validation Suite")
    print("=" * 60)
    
    # Change to project root (up two levels from this script)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    project_root = os.path.dirname(os.path.dirname(script_dir))
    os.chdir(project_root)
    print(f"Working directory: {os.getcwd()}\n")
    
    tests = [
        test_component_exists,
        test_component_structure,
        test_payload_completeness,
        test_documentation,
        test_configuration_files,
        test_component_features,
        test_styling,
        test_jsdoc_comments,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"✗ Test error: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"Validation Results: {passed} passed, {failed} failed")
    print("=" * 60)
    
    if failed == 0:
        print("\n✓ All validations passed!")
        print("Component is ready for integration.")
        print("\nNext steps:")
        print("1. Run 'npm install' to install dependencies")
        print("2. Run 'npm run build:tsx' to build the component")
        print("3. Integrate with Django templates using INTEGRATION_GUIDE.md")
    
    return 0 if failed == 0 else 1

if __name__ == '__main__':
    sys.exit(main())
