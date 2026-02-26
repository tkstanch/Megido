"""
Cloud infrastructure scanning engine for Data Tracer.
Implements AWS, Azure, GCP scanning, container security,
and multi-cloud asset discovery.
"""

import json
import re
import hashlib
from typing import Dict, List, Optional, Any
from datetime import datetime


# AWS Security checks
AWS_SECURITY_CHECKS = {
    's3': [
        {
            'check_id': 'S3-001',
            'name': 'Public S3 Bucket Access',
            'severity': 'critical',
            'description': 'S3 bucket is publicly accessible',
            'remediation': 'Set bucket ACL to private and use bucket policies to restrict access',
            'compliance': ['PCI-DSS 1.3', 'HIPAA §164.312'],
        },
        {
            'check_id': 'S3-002',
            'name': 'S3 Bucket Encryption Disabled',
            'severity': 'high',
            'description': 'S3 bucket does not have default encryption enabled',
            'remediation': 'Enable AES-256 or AWS KMS encryption for the bucket',
            'compliance': ['PCI-DSS 3.4', 'HIPAA §164.312'],
        },
        {
            'check_id': 'S3-003',
            'name': 'S3 Bucket Versioning Disabled',
            'severity': 'medium',
            'description': 'S3 bucket versioning is not enabled',
            'remediation': 'Enable versioning to protect against accidental deletion',
        },
        {
            'check_id': 'S3-004',
            'name': 'S3 Bucket Logging Disabled',
            'severity': 'medium',
            'description': 'S3 bucket access logging is not enabled',
            'remediation': 'Enable server access logging for audit trails',
        },
        {
            'check_id': 'S3-005',
            'name': 'S3 Bucket MFA Delete Disabled',
            'severity': 'medium',
            'description': 'MFA Delete is not enabled for S3 bucket',
            'remediation': 'Enable MFA Delete to prevent accidental/malicious deletion',
        },
    ],
    'iam': [
        {
            'check_id': 'IAM-001',
            'name': 'Root Account Usage',
            'severity': 'critical',
            'description': 'AWS root account is being used for day-to-day operations',
            'remediation': 'Create IAM users/roles for all operations; lock root account',
            'compliance': ['CIS AWS 1.1'],
        },
        {
            'check_id': 'IAM-002',
            'name': 'Root Account MFA Not Enabled',
            'severity': 'critical',
            'description': 'MFA is not enabled for the root account',
            'remediation': 'Enable hardware MFA on the root account immediately',
            'compliance': ['CIS AWS 1.5'],
        },
        {
            'check_id': 'IAM-003',
            'name': 'Overly Permissive IAM Policy',
            'severity': 'high',
            'description': 'IAM policy grants * permissions (admin access)',
            'remediation': 'Implement least-privilege access by specifying required permissions only',
            'compliance': ['CIS AWS 1.16'],
        },
        {
            'check_id': 'IAM-004',
            'name': 'IAM Password Policy Too Weak',
            'severity': 'medium',
            'description': 'IAM account password policy does not meet security requirements',
            'remediation': 'Set minimum 14-character passwords with complexity requirements',
            'compliance': ['CIS AWS 1.9'],
        },
        {
            'check_id': 'IAM-005',
            'name': 'Access Keys Not Rotated',
            'severity': 'medium',
            'description': 'IAM access keys have not been rotated in 90+ days',
            'remediation': 'Rotate access keys every 90 days and delete unused keys',
        },
    ],
    'ec2': [
        {
            'check_id': 'EC2-001',
            'name': 'Security Group Allows All Inbound Traffic',
            'severity': 'critical',
            'description': 'EC2 security group has 0.0.0.0/0 inbound rule',
            'remediation': 'Restrict inbound traffic to specific IP ranges and ports',
        },
        {
            'check_id': 'EC2-002',
            'name': 'EC2 Instance Public IP Exposed',
            'severity': 'medium',
            'description': 'EC2 instance has a public IP address',
            'remediation': 'Use private subnets with NAT for outbound traffic; expose via load balancer',
        },
        {
            'check_id': 'EC2-003',
            'name': 'EBS Volume Encryption Disabled',
            'severity': 'high',
            'description': 'EBS volume is not encrypted',
            'remediation': 'Enable EBS encryption using AWS KMS',
        },
        {
            'check_id': 'EC2-004',
            'name': 'IMDSv2 Not Enforced',
            'severity': 'medium',
            'description': 'EC2 instance does not enforce IMDSv2 (SSRF protection)',
            'remediation': 'Require IMDSv2 to mitigate SSRF attacks against metadata service',
            'cve': 'CVE-2019-1952',
        },
    ],
    'cloudtrail': [
        {
            'check_id': 'CT-001',
            'name': 'CloudTrail Not Enabled',
            'severity': 'critical',
            'description': 'AWS CloudTrail is not enabled in this region',
            'remediation': 'Enable CloudTrail in all regions for comprehensive audit logging',
            'compliance': ['CIS AWS 2.1'],
        },
        {
            'check_id': 'CT-002',
            'name': 'CloudTrail Log Validation Disabled',
            'severity': 'medium',
            'description': 'CloudTrail log file validation is not enabled',
            'remediation': 'Enable log file validation to detect tampering',
        },
    ],
}

# Azure security checks
AZURE_SECURITY_CHECKS = {
    'storage': [
        {
            'check_id': 'AZ-STG-001',
            'name': 'Azure Storage Blob Public Access',
            'severity': 'critical',
            'description': 'Azure storage container allows public blob access',
            'remediation': 'Disable public blob access and use SAS tokens for controlled access',
        },
        {
            'check_id': 'AZ-STG-002',
            'name': 'Azure Storage Not Encrypted with Customer Key',
            'severity': 'medium',
            'description': 'Storage account uses Microsoft-managed keys instead of customer-managed keys',
            'remediation': 'Configure customer-managed keys for enhanced control',
        },
    ],
    'nsg': [
        {
            'check_id': 'AZ-NSG-001',
            'name': 'NSG Allows Inbound SSH from Any',
            'severity': 'high',
            'description': 'Network Security Group allows SSH (22) from 0.0.0.0/0',
            'remediation': 'Restrict SSH access to specific IP ranges or use Azure Bastion',
        },
        {
            'check_id': 'AZ-NSG-002',
            'name': 'NSG Allows Inbound RDP from Any',
            'severity': 'high',
            'description': 'Network Security Group allows RDP (3389) from 0.0.0.0/0',
            'remediation': 'Restrict RDP access to specific IP ranges or use Azure Bastion',
        },
    ],
}

# GCP security checks
GCP_SECURITY_CHECKS = {
    'storage': [
        {
            'check_id': 'GCP-GCS-001',
            'name': 'GCS Bucket Publicly Accessible',
            'severity': 'critical',
            'description': 'Google Cloud Storage bucket is publicly accessible',
            'remediation': 'Remove allUsers and allAuthenticatedUsers from bucket IAM policy',
        },
    ],
    'iam': [
        {
            'check_id': 'GCP-IAM-001',
            'name': 'Service Account with Admin Role',
            'severity': 'high',
            'description': 'Service account has project-level admin/owner role',
            'remediation': 'Grant only required permissions using custom IAM roles',
        },
    ],
}

# Docker/Kubernetes security checks
CONTAINER_SECURITY_CHECKS = [
    {
        'check_id': 'CONT-001',
        'name': 'Container Running as Root',
        'severity': 'high',
        'description': 'Container process runs as root user',
        'remediation': 'Add USER directive in Dockerfile to run as non-root user',
        'cis_benchmark': 'CIS Docker 4.1',
    },
    {
        'check_id': 'CONT-002',
        'name': 'Container Image Not Pinned',
        'severity': 'medium',
        'description': 'Docker image uses "latest" tag instead of pinned digest',
        'remediation': 'Pin image to specific digest for reproducible deployments',
    },
    {
        'check_id': 'CONT-003',
        'name': 'Privileged Container',
        'severity': 'critical',
        'description': 'Container runs with --privileged flag',
        'remediation': 'Remove privileged flag and use specific capabilities if needed',
        'cis_benchmark': 'CIS Docker 5.4',
    },
    {
        'check_id': 'CONT-004',
        'name': 'Container Escape Risk - Mounted Docker Socket',
        'severity': 'critical',
        'description': 'Docker socket is mounted inside the container',
        'remediation': 'Never mount the Docker socket in containers',
        'cve': 'General container escape vector',
    },
    {
        'check_id': 'CONT-005',
        'name': 'Sensitive Environment Variables',
        'severity': 'high',
        'description': 'Container may have sensitive data in environment variables',
        'remediation': 'Use Kubernetes Secrets or HashiCorp Vault for sensitive configuration',
    },
    {
        'check_id': 'CONT-006',
        'name': 'No Resource Limits Set',
        'severity': 'medium',
        'description': 'Container has no CPU/memory resource limits',
        'remediation': 'Set resource limits to prevent resource exhaustion (DoS)',
        'cis_benchmark': 'CIS Kubernetes 5.2.3',
    },
]


class CloudScanner:
    """
    Cloud infrastructure scanning engine implementing multi-cloud
    security assessment for AWS, Azure, GCP, and containers.
    """

    def __init__(self):
        """Initialize the cloud scanner."""
        self.scan_results: List[Dict] = []
        self.aws_checks = AWS_SECURITY_CHECKS
        self.azure_checks = AZURE_SECURITY_CHECKS
        self.gcp_checks = GCP_SECURITY_CHECKS
        self.container_checks = CONTAINER_SECURITY_CHECKS

    def scan_aws(self, config: Optional[Dict] = None) -> Dict:
        """
        Scan AWS infrastructure for security issues.

        Args:
            config: AWS configuration (region, credentials, etc.)

        Returns:
            AWS security scan results
        """
        results = {
            'provider': 'AWS',
            'region': config.get('region', 'us-east-1') if config else 'us-east-1',
            'scan_timestamp': datetime.utcnow().isoformat(),
            'findings': [],
            'summary': {},
            'compliance': {},
        }

        # Enumerate S3 buckets (simulated)
        s3_findings = self._check_s3_security([
            {'name': 'my-public-bucket', 'acl': 'public-read', 'encrypted': False, 'versioned': False},
            {'name': 'my-private-bucket', 'acl': 'private', 'encrypted': True, 'versioned': True},
        ])
        results['findings'].extend(s3_findings)

        # Check IAM configuration
        iam_findings = self._check_iam_security({
            'root_mfa': False,
            'password_policy': {'min_length': 8, 'require_symbols': False},
            'unused_credentials': ['arn:aws:iam::123456789012:user/old-user'],
        })
        results['findings'].extend(iam_findings)

        # Check EC2 security groups
        sg_findings = self._check_security_groups([
            {
                'group_id': 'sg-12345678',
                'name': 'default',
                'inbound_rules': [
                    {'protocol': 'tcp', 'from_port': 22, 'to_port': 22, 'source': '0.0.0.0/0'},
                    {'protocol': '-1', 'from_port': 0, 'to_port': 0, 'source': '0.0.0.0/0'},
                ],
            }
        ])
        results['findings'].extend(sg_findings)

        # Summarize findings
        results['summary'] = self._summarize_findings(results['findings'])
        results['compliance'] = self._check_cis_aws_compliance(results['findings'])

        self.scan_results.append(results)
        return results

    def _check_s3_security(self, buckets: List[Dict]) -> List[Dict]:
        """Check S3 bucket security configurations."""
        findings = []
        for bucket in buckets:
            bucket_name = bucket.get('name', 'unknown')

            if bucket.get('acl') in ['public-read', 'public-read-write']:
                findings.append({
                    'resource': f's3://{bucket_name}',
                    'check_id': 'S3-001',
                    'name': 'Public S3 Bucket Access',
                    'severity': 'critical',
                    'description': f'S3 bucket {bucket_name} is publicly accessible (ACL: {bucket["acl"]})',
                    'remediation': 'Set bucket ACL to private and use bucket policies',
                })

            if not bucket.get('encrypted'):
                findings.append({
                    'resource': f's3://{bucket_name}',
                    'check_id': 'S3-002',
                    'name': 'S3 Bucket Encryption Disabled',
                    'severity': 'high',
                    'description': f'S3 bucket {bucket_name} does not have encryption enabled',
                    'remediation': 'Enable AES-256 or AWS KMS encryption',
                })

            if not bucket.get('versioned'):
                findings.append({
                    'resource': f's3://{bucket_name}',
                    'check_id': 'S3-003',
                    'name': 'S3 Bucket Versioning Disabled',
                    'severity': 'medium',
                    'description': f'S3 bucket {bucket_name} does not have versioning enabled',
                    'remediation': 'Enable versioning for data protection',
                })

        return findings

    def _check_iam_security(self, iam_config: Dict) -> List[Dict]:
        """Check IAM security configuration."""
        findings = []

        if not iam_config.get('root_mfa'):
            findings.append({
                'resource': 'iam::root',
                'check_id': 'IAM-002',
                'name': 'Root Account MFA Not Enabled',
                'severity': 'critical',
                'description': 'MFA is not enabled for the AWS root account',
                'remediation': 'Enable hardware MFA on root account',
            })

        password_policy = iam_config.get('password_policy', {})
        if password_policy.get('min_length', 0) < 14:
            findings.append({
                'resource': 'iam::password-policy',
                'check_id': 'IAM-004',
                'name': 'IAM Password Policy Too Weak',
                'severity': 'medium',
                'description': f'Password minimum length is {password_policy.get("min_length", "not set")} (should be 14+)',
                'remediation': 'Set minimum password length to 14 characters',
            })

        return findings

    def _check_security_groups(self, security_groups: List[Dict]) -> List[Dict]:
        """Check EC2 security group configurations."""
        findings = []

        for sg in security_groups:
            for rule in sg.get('inbound_rules', []):
                source = rule.get('source', '')
                if source in ['0.0.0.0/0', '::/0']:
                    protocol = rule.get('protocol', '')
                    from_port = rule.get('from_port', 0)

                    if protocol == '-1' or (from_port == 0 and rule.get('to_port', 0) == 0):
                        findings.append({
                            'resource': f"ec2::security-group::{sg.get('group_id')}",
                            'check_id': 'EC2-001',
                            'name': 'Security Group Allows All Inbound Traffic',
                            'severity': 'critical',
                            'description': f'Security group {sg.get("name")} allows all inbound traffic from {source}',
                            'remediation': 'Restrict inbound traffic to specific IPs and ports',
                        })
                    elif from_port == 22:
                        findings.append({
                            'resource': f"ec2::security-group::{sg.get('group_id')}",
                            'check_id': 'EC2-001-SSH',
                            'name': 'SSH Open to the Internet',
                            'severity': 'high',
                            'description': f'Security group {sg.get("name")} allows SSH from anywhere',
                            'remediation': 'Restrict SSH access to specific IP ranges',
                        })
                    elif from_port == 3389:
                        findings.append({
                            'resource': f"ec2::security-group::{sg.get('group_id')}",
                            'check_id': 'EC2-001-RDP',
                            'name': 'RDP Open to the Internet',
                            'severity': 'high',
                            'description': f'Security group {sg.get("name")} allows RDP from anywhere',
                            'remediation': 'Restrict RDP access to specific IP ranges',
                        })

        return findings

    def scan_azure(self, config: Optional[Dict] = None) -> Dict:
        """
        Scan Azure infrastructure for security issues.

        Args:
            config: Azure configuration

        Returns:
            Azure security scan results
        """
        results = {
            'provider': 'Azure',
            'subscription': config.get('subscription_id', 'unknown') if config else 'unknown',
            'scan_timestamp': datetime.utcnow().isoformat(),
            'findings': [],
            'summary': {},
        }

        # Check storage accounts
        storage_findings = self._check_azure_storage([
            {'name': 'mystorageaccount', 'public_access': True, 'https_only': False},
        ])
        results['findings'].extend(storage_findings)

        # Check NSGs
        nsg_findings = self._check_azure_nsgs([
            {
                'name': 'default-nsg',
                'rules': [
                    {'name': 'AllowSSH', 'protocol': 'Tcp', 'destination_port': '22', 'source': '*'},
                ]
            }
        ])
        results['findings'].extend(nsg_findings)

        results['summary'] = self._summarize_findings(results['findings'])
        self.scan_results.append(results)
        return results

    def _check_azure_storage(self, storage_accounts: List[Dict]) -> List[Dict]:
        """Check Azure storage account security."""
        findings = []
        for account in storage_accounts:
            if account.get('public_access'):
                findings.append({
                    'resource': f"azure::storage::{account['name']}",
                    'check_id': 'AZ-STG-001',
                    'name': 'Azure Storage Blob Public Access',
                    'severity': 'critical',
                    'description': f'Storage account {account["name"]} allows public blob access',
                    'remediation': 'Disable public blob access on storage account',
                })
            if not account.get('https_only'):
                findings.append({
                    'resource': f"azure::storage::{account['name']}",
                    'check_id': 'AZ-STG-003',
                    'name': 'Storage Account Allows HTTP',
                    'severity': 'medium',
                    'description': f'Storage account {account["name"]} does not enforce HTTPS',
                    'remediation': 'Enable "Secure transfer required" on storage account',
                })
        return findings

    def _check_azure_nsgs(self, nsgs: List[Dict]) -> List[Dict]:
        """Check Azure Network Security Group rules."""
        findings = []
        for nsg in nsgs:
            for rule in nsg.get('rules', []):
                if rule.get('source') == '*':
                    port = rule.get('destination_port', '')
                    check_id = 'AZ-NSG-001' if port == '22' else 'AZ-NSG-002' if port == '3389' else 'AZ-NSG-003'
                    service = 'SSH' if port == '22' else 'RDP' if port == '3389' else f'port {port}'
                    findings.append({
                        'resource': f"azure::nsg::{nsg['name']}",
                        'check_id': check_id,
                        'name': f'NSG Allows {service} from Any',
                        'severity': 'high',
                        'description': f'NSG {nsg["name"]} allows {service} from any IP',
                        'remediation': f'Restrict {service} to specific IP ranges',
                    })
        return findings

    def scan_gcp(self, config: Optional[Dict] = None) -> Dict:
        """
        Scan GCP infrastructure for security issues.

        Args:
            config: GCP configuration

        Returns:
            GCP security scan results
        """
        results = {
            'provider': 'GCP',
            'project': config.get('project_id', 'unknown') if config else 'unknown',
            'scan_timestamp': datetime.utcnow().isoformat(),
            'findings': [],
            'summary': {},
        }

        # Simulate GCP scan
        results['findings'].append({
            'resource': 'gcp::compute::firewall',
            'check_id': 'GCP-FW-001',
            'name': 'Firewall Rule Allows SSH from Internet',
            'severity': 'high',
            'description': 'GCP firewall rule allows SSH (22) from 0.0.0.0/0',
            'remediation': 'Restrict SSH to specific IP ranges or use Identity-Aware Proxy',
        })

        results['summary'] = self._summarize_findings(results['findings'])
        self.scan_results.append(results)
        return results

    def scan_containers(self, images: Optional[List[Dict]] = None) -> Dict:
        """
        Scan Docker/Kubernetes containers for security issues.

        Args:
            images: List of container images to scan

        Returns:
            Container security scan results
        """
        results = {
            'platform': 'Containers',
            'scan_timestamp': datetime.utcnow().isoformat(),
            'findings': [],
            'images': [],
            'kubernetes_findings': [],
        }

        # Check container configurations
        sample_containers = images or [
            {
                'image': 'nginx:latest',
                'running_as_root': True,
                'privileged': False,
                'resource_limits': None,
                'env_vars': ['DB_PASSWORD=secret123', 'API_KEY=abc123'],
            }
        ]

        for container in sample_containers:
            findings = self._check_container_security(container)
            results['findings'].extend(findings)
            results['images'].append({
                'image': container.get('image'),
                'finding_count': len(findings),
                'critical_count': sum(1 for f in findings if f.get('severity') == 'critical'),
            })

        # Kubernetes checks
        k8s_findings = self._check_kubernetes_security({
            'rbac_enabled': True,
            'pod_security_policy': False,
            'network_policies': False,
        })
        results['kubernetes_findings'] = k8s_findings

        results['summary'] = self._summarize_findings(results['findings'] + results['kubernetes_findings'])
        self.scan_results.append(results)
        return results

    def _check_container_security(self, container: Dict) -> List[Dict]:
        """Check container security configuration."""
        findings = []
        image = container.get('image', 'unknown')

        if container.get('running_as_root'):
            findings.append({
                'resource': f'container::{image}',
                'check_id': 'CONT-001',
                'name': 'Container Running as Root',
                'severity': 'high',
                'description': f'Container {image} runs as root user',
                'remediation': 'Add USER directive in Dockerfile to run as non-root',
            })

        if container.get('privileged'):
            findings.append({
                'resource': f'container::{image}',
                'check_id': 'CONT-003',
                'name': 'Privileged Container',
                'severity': 'critical',
                'description': f'Container {image} runs in privileged mode',
                'remediation': 'Remove privileged flag and use specific Linux capabilities',
            })

        if not container.get('resource_limits'):
            findings.append({
                'resource': f'container::{image}',
                'check_id': 'CONT-006',
                'name': 'No Resource Limits',
                'severity': 'medium',
                'description': f'Container {image} has no CPU/memory resource limits',
                'remediation': 'Set resource limits to prevent resource exhaustion',
            })

        # Check for secrets in environment variables
        secret_patterns = [re.compile(r'(password|secret|key|token|api|pwd)', re.IGNORECASE)]
        for env_var in container.get('env_vars', []):
            for pattern in secret_patterns:
                if pattern.search(env_var.split('=')[0] if '=' in env_var else env_var):
                    findings.append({
                        'resource': f'container::{image}',
                        'check_id': 'CONT-005',
                        'name': 'Sensitive Data in Environment Variables',
                        'severity': 'high',
                        'description': f'Container {image} may have sensitive data in env vars',
                        'remediation': 'Use Kubernetes Secrets or HashiCorp Vault',
                    })
                    break

        # Check for unpinned image
        if ':latest' in image or ':' not in image:
            findings.append({
                'resource': f'container::{image}',
                'check_id': 'CONT-002',
                'name': 'Container Image Not Pinned',
                'severity': 'medium',
                'description': f'Container {image} uses unpinned image tag',
                'remediation': 'Pin image to specific digest (sha256:...)',
            })

        return findings

    def _check_kubernetes_security(self, k8s_config: Dict) -> List[Dict]:
        """Check Kubernetes security configuration."""
        findings = []

        if not k8s_config.get('pod_security_policy'):
            findings.append({
                'resource': 'kubernetes::pod-security-policy',
                'check_id': 'K8S-001',
                'name': 'Pod Security Policy Not Configured',
                'severity': 'high',
                'description': 'Kubernetes Pod Security Policies are not configured',
                'remediation': 'Implement Pod Security Standards (restricted profile)',
            })

        if not k8s_config.get('network_policies'):
            findings.append({
                'resource': 'kubernetes::network-policy',
                'check_id': 'K8S-002',
                'name': 'No Network Policies Defined',
                'severity': 'medium',
                'description': 'Kubernetes Network Policies are not configured - all pods can communicate',
                'remediation': 'Implement network policies to restrict pod-to-pod communication',
            })

        return findings

    def _summarize_findings(self, findings: List[Dict]) -> Dict:
        """Summarize findings by severity."""
        summary = {
            'total': len(findings),
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
        }

        for finding in findings:
            severity = finding.get('severity', 'info').lower()
            if severity in summary:
                summary[severity] += 1

        summary['risk_score'] = min(10.0, (
            summary['critical'] * 2.0 +
            summary['high'] * 1.0 +
            summary['medium'] * 0.5 +
            summary['low'] * 0.1
        ))

        return summary

    def _check_cis_aws_compliance(self, findings: List[Dict]) -> Dict:
        """Check AWS CIS Benchmark compliance."""
        check_ids = [f.get('check_id', '') for f in findings]

        # CIS AWS Benchmark Level 1 checks
        cis_level1 = ['IAM-001', 'IAM-002', 'IAM-003', 'IAM-004', 'CT-001', 'EC2-001']
        failed = [c for c in cis_level1 if c in check_ids]
        passed = [c for c in cis_level1 if c not in check_ids]

        return {
            'framework': 'CIS AWS Foundations Benchmark v2.0',
            'failed_checks': failed,
            'passed_checks': passed,
            'compliance_percentage': round((len(passed) / len(cis_level1)) * 100, 1) if cis_level1 else 100,
        }

    def enumerate_cloud_assets(self, provider: str, config: Optional[Dict] = None) -> List[Dict]:
        """
        Enumerate cloud assets across a provider.

        Args:
            provider: Cloud provider (aws, azure, gcp)
            config: Provider configuration

        Returns:
            List of discovered cloud assets
        """
        assets = []

        if provider.lower() == 'aws':
            # Simulate AWS asset discovery
            assets.extend([
                {'type': 's3_bucket', 'name': 'my-data-bucket', 'region': 'us-east-1', 'public': False},
                {'type': 'ec2_instance', 'id': 'i-12345678', 'type_name': 't3.micro', 'region': 'us-east-1'},
                {'type': 'rds_instance', 'id': 'mydb', 'engine': 'mysql', 'region': 'us-east-1'},
                {'type': 'lambda_function', 'name': 'my-function', 'runtime': 'python3.12', 'region': 'us-east-1'},
            ])
        elif provider.lower() == 'azure':
            assets.extend([
                {'type': 'storage_account', 'name': 'mystorageacct', 'location': 'eastus'},
                {'type': 'virtual_machine', 'name': 'myvm', 'size': 'Standard_B2s', 'location': 'eastus'},
                {'type': 'app_service', 'name': 'myapp', 'tier': 'Standard', 'location': 'eastus'},
            ])
        elif provider.lower() == 'gcp':
            assets.extend([
                {'type': 'cloud_storage_bucket', 'name': 'my-gcs-bucket', 'location': 'us-central1'},
                {'type': 'compute_instance', 'name': 'my-vm', 'machine_type': 'n1-standard-1', 'zone': 'us-central1-a'},
                {'type': 'cloud_run_service', 'name': 'my-service', 'region': 'us-central1'},
            ])

        return assets
