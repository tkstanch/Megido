"""
Custom Bypass Technique Parser and Executor
Allows users to craft custom bypass techniques with template-based transformations.
"""

import re
from typing import Dict, Any, Optional, List
from .encoding import EncodingTechniques


class TechniqueParser:
    """Parser for custom bypass technique templates"""
    
    # Supported transformation functions
    TRANSFORMATIONS = {
        'url_encode': EncodingTechniques.url_encode_single,
        'url_encode_double': EncodingTechniques.url_encode_double,
        'url_encode_triple': EncodingTechniques.url_encode_triple,
        'html_decimal': EncodingTechniques.html_entity_decimal,
        'html_hex': EncodingTechniques.html_entity_hex,
        'html5_entity': EncodingTechniques.html5_named_entities,
        'unicode': EncodingTechniques.unicode_escape,
        'base64': EncodingTechniques.base64_encode,
        'hex': EncodingTechniques.hex_encode,
        'null_byte': EncodingTechniques.null_byte_injection,
        'html_comment': EncodingTechniques.comment_insertion_html,
        'sql_comment': EncodingTechniques.comment_insertion_sql,
        'utf7': EncodingTechniques.utf7_encode,
        'upper': lambda text: text.upper(),
        'lower': lambda text: text.lower(),
        'reverse': lambda text: text[::-1],
    }
    
    @staticmethod
    def validate_template(template: str) -> tuple[bool, str]:
        """
        Validate a technique template for security and syntax.
        
        Args:
            template: The template string to validate
            
        Returns:
            Tuple of (is_valid, error_message)
        """
        if not template or not isinstance(template, str):
            return False, "Template must be a non-empty string"
        
        # Check for potentially dangerous patterns
        dangerous_patterns = [
            r'__import__',
            r'eval\(',
            r'exec\(',
            r'compile\(',
            r'globals\(',
            r'locals\(',
            r'__.*__',  # Dunder methods
            r'os\.',
            r'sys\.',
            r'subprocess',
            r'open\(',
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, template, re.IGNORECASE):
                return False, f"Template contains potentially dangerous pattern: {pattern}"
        
        # Check for valid placeholder syntax
        # Valid: {{payload}}, {{char}}, {{payload|url_encode}}, {{char|html_hex|base64}}
        placeholder_pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_]*(?:\|[a-zA-Z_][a-zA-Z0-9_]*)*)\}\}'
        placeholders = re.findall(placeholder_pattern, template)
        
        if not placeholders:
            return False, "Template must contain at least one placeholder (e.g., {{payload}} or {{char}})"
        
        # Validate transformations
        for placeholder in placeholders:
            parts = placeholder.split('|')
            var_name = parts[0]
            
            # Valid variable names
            if var_name not in ['payload', 'char', 'target', 'param']:
                return False, f"Invalid variable name: {var_name}. Use 'payload', 'char', 'target', or 'param'"
            
            # Validate transformation functions
            for transform in parts[1:]:
                if transform not in TechniqueParser.TRANSFORMATIONS:
                    return False, f"Unknown transformation function: {transform}"
        
        return True, "Template is valid"
    
    @staticmethod
    def parse_and_execute(template: str, variables: Dict[str, Any]) -> tuple[bool, str, str]:
        """
        Parse and execute a technique template with provided variables.
        
        Args:
            template: The technique template
            variables: Dictionary of variable values (e.g., {'payload': '<script>', 'char': '<'})
            
        Returns:
            Tuple of (success, result, error_message)
        """
        try:
            # First validate the template
            is_valid, error_msg = TechniqueParser.validate_template(template)
            if not is_valid:
                return False, "", error_msg
            
            result = template
            
            # Find all placeholders
            placeholder_pattern = r'\{\{([a-zA-Z_][a-zA-Z0-9_]*(?:\|[a-zA-Z_][a-zA-Z0-9_]*)*)\}\}'
            
            def replace_placeholder(match):
                placeholder = match.group(1)
                parts = placeholder.split('|')
                var_name = parts[0]
                transformations = parts[1:]
                
                # Get the variable value
                if var_name not in variables:
                    return f"{{{{MISSING:{var_name}}}}}"
                
                value = str(variables[var_name])
                
                # Apply transformations in order
                for transform in transformations:
                    if transform in TechniqueParser.TRANSFORMATIONS:
                        try:
                            value = TechniqueParser.TRANSFORMATIONS[transform](value)
                        except Exception as e:
                            return f"{{{{ERROR:{transform}:{str(e)}}}}}"
                
                return value
            
            # Replace all placeholders
            result = re.sub(placeholder_pattern, replace_placeholder, result)
            
            # Check if any errors occurred during replacement
            if 'MISSING:' in result or 'ERROR:' in result:
                return False, result, "Error during template execution - check placeholders"
            
            return True, result, ""
            
        except Exception as e:
            return False, "", f"Unexpected error: {str(e)}"
    
    @staticmethod
    def get_available_transformations() -> Dict[str, str]:
        """Get list of available transformation functions with descriptions"""
        return {
            'url_encode': 'Single URL encoding (%3C)',
            'url_encode_double': 'Double URL encoding (%253C)',
            'url_encode_triple': 'Triple URL encoding (%25253C)',
            'html_decimal': 'HTML entity decimal (&#60;)',
            'html_hex': 'HTML entity hexadecimal (&#x3c;)',
            'html5_entity': 'HTML5 named entities (&lt;)',
            'unicode': 'Unicode escape (\\u003c)',
            'base64': 'Base64 encoding',
            'hex': 'Hexadecimal encoding (\\x3c)',
            'null_byte': 'Append null byte (%00)',
            'html_comment': 'Insert HTML comments between characters',
            'sql_comment': 'Insert SQL comments between characters',
            'utf7': 'UTF-7 encoding',
            'upper': 'Convert to uppercase',
            'lower': 'Convert to lowercase',
            'reverse': 'Reverse the string',
        }
    
    @staticmethod
    def get_available_variables() -> Dict[str, str]:
        """Get list of available template variables with descriptions"""
        return {
            'payload': 'The main payload to test',
            'char': 'A single character to test',
            'target': 'The target URL',
            'param': 'The parameter name being tested',
        }


class TechniqueBuilder:
    """Helper class to build bypass techniques programmatically"""
    
    @staticmethod
    def create_chained_encoding(encodings: list) -> str:
        """
        Create a technique that chains multiple encodings.
        
        Args:
            encodings: List of encoding names to chain
            
        Returns:
            Template string
        """
        chain = '|'.join(encodings)
        return f"{{{{payload|{chain}}}}}"
    
    @staticmethod
    def create_mixed_technique(parts: list) -> str:
        """
        Create a technique that mixes literal text with encoded payloads.
        
        Args:
            parts: List of dictionaries with 'type' and 'value' keys
                   type can be 'literal' or 'template'
                   
        Returns:
            Template string
        """
        result = []
        for part in parts:
            if part['type'] == 'literal':
                result.append(part['value'])
            elif part['type'] == 'template':
                result.append(part['value'])
        return ''.join(result)
    
    @staticmethod
    def create_split_technique(payload_var: str, splitter: str, encoding: str = None) -> str:
        """
        Create a technique that splits the payload with a separator.
        
        Args:
            payload_var: Variable name (e.g., 'payload' or 'char')
            splitter: String to insert between characters
            encoding: Optional encoding to apply first
            
        Returns:
            Template string
        """
        if encoding:
            return f"{splitter}{{{{{{{{payload_var}}}}|{encoding}}}}}{splitter}"
        return f"{splitter}{{{{{{{payload_var}}}}}}}{splitter}"


def test_technique(technique_template: str, test_payload: str) -> Dict[str, Any]:
    """
    Test a technique template with a sample payload.
    
    Args:
        technique_template: The template to test
        test_payload: Sample payload to use
        
    Returns:
        Dictionary with test results
    """
    parser = TechniqueParser()
    
    # Validate
    is_valid, validation_msg = parser.validate_template(technique_template)
    
    if not is_valid:
        return {
            'success': False,
            'error': validation_msg,
            'result': None
        }
    
    # Execute
    success, result, error = parser.parse_and_execute(
        technique_template,
        {'payload': test_payload, 'char': test_payload[0] if test_payload else ''}
    )
    
    return {
        'success': success,
        'error': error if not success else None,
        'result': result,
        'original': test_payload
    }


class PayloadManipulator:
    """Helper class to manipulate and transform ready-made payloads"""
    
    @staticmethod
    def apply_transformations(payload: str, transformations: List[str]) -> tuple[bool, str, str]:
        """
        Apply a list of transformations to a payload.
        
        Args:
            payload: The original payload
            transformations: List of transformation names to apply
            
        Returns:
            Tuple of (success, transformed_payload, error_message)
        """
        result = payload
        
        for transform in transformations:
            if transform not in TechniqueParser.TRANSFORMATIONS:
                return False, payload, f"Unknown transformation: {transform}"
            
            try:
                result = TechniqueParser.TRANSFORMATIONS[transform](result)
            except Exception as e:
                return False, payload, f"Error applying {transform}: {str(e)}"
        
        return True, result, ""
    
    @staticmethod
    def apply_technique_to_payload(payload: str, technique_template: str) -> tuple[bool, str, str]:
        """
        Apply a custom technique template to a payload.
        
        Args:
            payload: The payload to transform
            technique_template: Template string like "{{payload|url_encode|html_hex}}"
            
        Returns:
            Tuple of (success, result, error_message)
        """
        parser = TechniqueParser()
        
        # Validate template
        is_valid, validation_msg = parser.validate_template(technique_template)
        if not is_valid:
            return False, payload, validation_msg
        
        # Execute template with payload
        success, result, error = parser.parse_and_execute(
            technique_template,
            {'payload': payload, 'char': payload[0] if payload else ''}
        )
        
        return success, result, error
    
    @staticmethod
    def combine_payloads(payloads: List[str], separator: str = '', 
                        transformations: Optional[List[str]] = None) -> tuple[bool, str, str]:
        """
        Combine multiple payloads with optional transformations.
        
        Args:
            payloads: List of payload strings to combine
            separator: String to use between payloads
            transformations: Optional list of transformations to apply to combined payload
            
        Returns:
            Tuple of (success, combined_payload, error_message)
        """
        if not payloads:
            return False, "", "No payloads provided"
        
        # Combine payloads
        combined = separator.join(payloads)
        
        # Apply transformations if provided
        if transformations:
            return PayloadManipulator.apply_transformations(combined, transformations)
        
        return True, combined, ""
    
    @staticmethod
    def fuzz_payload(payload: str, fuzz_type: str = 'case') -> List[str]:
        """
        Generate fuzzed variants of a payload.
        
        Args:
            payload: Original payload
            fuzz_type: Type of fuzzing ('case', 'encoding', 'whitespace', 'all')
            
        Returns:
            List of fuzzed payload variants
        """
        variants = []
        
        if fuzz_type in ['case', 'all']:
            # Case variations
            variants.append(payload.upper())
            variants.append(payload.lower())
            variants.append(''.join([c.upper() if i % 2 == 0 else c.lower() 
                                    for i, c in enumerate(payload)]))
        
        if fuzz_type in ['encoding', 'all']:
            # Encoding variations
            try:
                variants.append(TechniqueParser.TRANSFORMATIONS['url_encode'](payload))
                variants.append(TechniqueParser.TRANSFORMATIONS['html_hex'](payload))
                variants.append(TechniqueParser.TRANSFORMATIONS['unicode'](payload))
            except:
                pass
        
        if fuzz_type in ['whitespace', 'all']:
            # Whitespace variations
            variants.append(payload.replace(' ', '\t'))
            variants.append(payload.replace(' ', '\n'))
            variants.append(payload.replace(' ', ''))
        
        # Remove duplicates and return
        return list(set(variants))
    
    @staticmethod
    def mutate_payload(payload: str, mutation_type: str = 'character') -> List[str]:
        """
        Generate mutated variants of a payload for bypass testing.
        
        Args:
            payload: Original payload
            mutation_type: Type of mutation ('character', 'comment', 'concatenation')
            
        Returns:
            List of mutated payload variants
        """
        mutations = []
        
        if mutation_type == 'character':
            # Character substitution mutations
            mutations.append(payload.replace('<', '%3C'))
            mutations.append(payload.replace('>', '%3E'))
            mutations.append(payload.replace('"', '%22'))
            mutations.append(payload.replace("'", '%27'))
        
        elif mutation_type == 'comment':
            # Comment insertion mutations
            try:
                mutations.append(TechniqueParser.TRANSFORMATIONS['html_comment'](payload))
                mutations.append(TechniqueParser.TRANSFORMATIONS['sql_comment'](payload))
            except:
                pass
        
        elif mutation_type == 'concatenation':
            # String concatenation for different contexts
            if 'script' in payload.lower():
                # JavaScript context
                mutations.append(payload.replace('alert', 'a'+'lert'))
                mutations.append(payload.replace('(', '['+']('))
            if 'select' in payload.lower() or 'union' in payload.lower():
                # SQL context
                mutations.append(payload.replace('SELECT', 'SE'+'LECT'))
                mutations.append(payload.replace('UNION', 'UN'+'ION'))
        
        return mutations
    
    @staticmethod
    def get_payload_variants(payload: str, include_fuzz: bool = True, 
                            include_mutations: bool = True) -> List[str]:
        """
        Generate all variants of a payload for comprehensive testing.
        
        Args:
            payload: Original payload
            include_fuzz: Include fuzzed variants
            include_mutations: Include mutated variants
            
        Returns:
            List of all payload variants
        """
        variants = [payload]  # Start with original
        
        if include_fuzz:
            variants.extend(PayloadManipulator.fuzz_payload(payload, 'all'))
        
        if include_mutations:
            for mut_type in ['character', 'comment', 'concatenation']:
                variants.extend(PayloadManipulator.mutate_payload(payload, mut_type))
        
        # Remove duplicates while preserving order
        seen = set()
        unique_variants = []
        for variant in variants:
            if variant not in seen:
                seen.add(variant)
                unique_variants.append(variant)
        
        return unique_variants
