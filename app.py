# ==================== requirements.txt ====================
# Create this file with the following content:

Flask==3.0.0
flask-cors==4.0.0
gunicorn==21.2.0


# ==================== render.yaml ====================
# Create this file for automatic deployment configuration:

services:
  - type: web
    name: cloud-risk-webservice
    env: python
    buildCommand: pip install -r requirements.txt
    startCommand: gunicorn app:app
    envVars:
      - key: PYTHON_VERSION
        value: 3.11.0


# ==================== app.py ====================
# Your main Flask application (already created)

from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime
import json
from collections import defaultdict
import os

app = Flask(__name__)
CORS(app)

# In-memory database (replace with MongoDB in production)
resources_db = {}
rules_db = {}
findings_db = []

# ==================== UTILITY FUNCTIONS ====================

def validate_resource(resource):
    """Validate required fields in resource object"""
    required_fields = ['_id', 'type', 'cloud', 'account_id', 'name', 'region']
    
    for field in required_fields:
        if field not in resource:
            return False, f"Missing required field: {field}"
    
    valid_clouds = ['aws', 'azure', 'gcp']
    if resource['cloud'] not in valid_clouds:
        return False, f"Invalid cloud provider. Must be one of: {', '.join(valid_clouds)}"
    
    return True, None


def calculate_severity_score(resource):
    """Calculate severity score based on resource properties"""
    score = 0
    reasons = []
    
    if resource.get('public_access', False) or resource.get('publicly_accessible', False):
        score += 30
        reasons.append("publicly_accessible")
    
    if not resource.get('encryption', True) and not resource.get('encryption_enabled', True):
        score += 25
        reasons.append("unencrypted")
    
    if resource.get('type') == 's3_bucket' and not resource.get('versioning', True):
        score += 15
        reasons.append("no_versioning")
    
    if resource.get('type') == 'ec2_instance' and not resource.get('ebs_encrypted', True):
        score += 25
        reasons.append("unencrypted_ebs")
    
    if resource.get('type') == 'iam_role' and resource.get('allow_wildcard_actions', False):
        score += 40
        reasons.append("wildcard_permissions")
    
    os_patch_days = resource.get('os_patch_days', 0)
    if os_patch_days > 90:
        score += 20
        reasons.append("outdated_patches")
    
    return score, reasons


def evaluate_rule(resource, rule):
    """Evaluate a single rule against a resource"""
    if resource.get('type') != rule.get('resource_type'):
        return False
    
    logic = rule.get('logic', {})
    field = logic.get('field')
    op = logic.get('op')
    value = logic.get('value')
    
    if field not in resource:
        return False
    
    resource_value = resource[field]
    
    if op == 'eq':
        return resource_value == value
    elif op == 'ne':
        return resource_value != value
    elif op == 'gt':
        return resource_value > value
    elif op == 'lt':
        return resource_value < value
    elif op == 'gte':
        return resource_value >= value
    elif op == 'lte':
        return resource_value <= value
    
    return False


def match_filter(resource, filter_dict):
    """Check if resource matches filter criteria"""
    for key, value in filter_dict.items():
        if '.' in key:
            parts = key.split('.')
            resource_value = resource
            for part in parts:
                if isinstance(resource_value, dict) and part in resource_value:
                    resource_value = resource_value[part]
                else:
                    return False
            if resource_value != value:
                return False
        else:
            if key not in resource or resource[key] != value:
                return False
    return True


# ==================== API ENDPOINTS ====================

@app.route('/', methods=['GET'])
def home():
    """Home endpoint with API documentation"""
    return jsonify({
        "service": "Cloud Risk WebService API",
        "version": "1.0.0",
        "status": "running",
        "endpoints": {
            "health": "GET /healthStatus",
            "upload_resources": "POST /uploadResources",
            "list_resources": "POST /listResources",
            "upload_rules": "POST /uploadRules",
            "scan": "GET /scanResources",
            "findings": "POST /findings",
            "severity_status": "GET /getSeverityStatus",
            "issues_by_type": "GET /getIssuesBasedOnResourceTypes",
            "issues_by_region": "GET /getIssuesBasedOnRegions",
            "load_sample": "POST /loadSampleData"
        },
        "documentation": "https://github.com/your-repo/cloud-risk-api"
    }), 200


@app.route('/healthStatus', methods=['GET'])
def health_status():
    """Health check endpoint"""
    return jsonify({
        "status": "Cloud Risk Service is running",
        "timestamp": datetime.utcnow().isoformat(),
        "resources_count": len(resources_db),
        "rules_count": len(rules_db),
        "findings_count": len(findings_db)
    }), 200


@app.route('/uploadResources', methods=['POST'])
def upload_resources():
    """Upload cloud resources"""
    try:
        data = request.get_json()
        
        if not data or 'resources' not in data:
            return jsonify({"error": "Invalid request. 'resources' array is required"}), 400
        
        resources = data['resources']
        
        if not isinstance(resources, list):
            return jsonify({"error": "'resources' must be an array"}), 400
        
        inserted_count = 0
        
        for resource in resources:
            is_valid, error_msg = validate_resource(resource)
            if not is_valid:
                continue
            
            if 'ingested_at' not in resource:
                resource['ingested_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            severity_score, scanner_reasons = calculate_severity_score(resource)
            resource['severity_score'] = severity_score
            resource['scanner_reasons'] = scanner_reasons
            resource['updated_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
            
            resources_db[resource['_id']] = resource
            inserted_count += 1
        
        return jsonify({"inserted_count": inserted_count}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/listResources', methods=['POST'])
def list_resources():
    """List resources with filtering, pagination, and search"""
    try:
        data = request.get_json() or {}
        
        filter_dict = data.get('filter', {})
        page_number = data.get('page_number', 1)
        page_size = data.get('page_size', 10)
        sort_by = data.get('sort_by', 'name')
        sort_order = data.get('sort_order', 'asc')
        search_str = data.get('search_str', '').lower()
        
        filtered_resources = []
        for resource in resources_db.values():
            if filter_dict and not match_filter(resource, filter_dict):
                continue
            
            if search_str:
                searchable = f"{resource.get('name', '')} {resource.get('_id', '')}".lower()
                if search_str not in searchable:
                    continue
            
            filtered_resources.append(resource)
        
        reverse = (sort_order == 'desc')
        if sort_by in ['name', 'type', 'region', 'severity_score']:
            filtered_resources.sort(
                key=lambda x: x.get(sort_by, ''),
                reverse=reverse
            )
        
        total_count = len(filtered_resources)
        total_pages = (total_count + page_size - 1) // page_size
        start_idx = (page_number - 1) * page_size
        end_idx = start_idx + page_size
        paginated_resources = filtered_resources[start_idx:end_idx]
        
        return jsonify({
            "current_page": page_number,
            "resources": paginated_resources,
            "total_count": total_count,
            "total_pages": total_pages
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/uploadRules', methods=['POST'])
def upload_rules():
    """Upload security rules"""
    try:
        data = request.get_json()
        
        if not data or 'rules' not in data:
            return jsonify({"error": "Invalid request. 'rules' array is required"}), 400
        
        rules = data['rules']
        uploaded_count = 0
        
        for rule in rules:
            if 'rule_id' in rule:
                rules_db[rule['rule_id']] = rule
                uploaded_count += 1
        
        return jsonify({"uploaded_count": uploaded_count}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/scanResources', methods=['GET'])
def scan_resources():
    """Perform security scan on all resources"""
    try:
        global findings_db
        findings_db = []
        issues_found = 0
        
        for resource in resources_db.values():
            for rule in rules_db.values():
                if evaluate_rule(resource, rule):
                    finding = {
                        "rule_id": rule['rule_id'],
                        "title": rule['title'],
                        "severity": rule['severity'],
                        "description": rule['description'],
                        "resource_type": rule['resource_type'],
                        "resource_id": resource['_id'],
                        "resource_name": resource['name'],
                        "region": resource['region'],
                        "account_id": resource['account_id'],
                        "status": "OPEN",
                        "detected_at": datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
                    }
                    findings_db.append(finding)
                    issues_found += 1
        
        return jsonify({
            "status": "Scan completed",
            "issues_found": issues_found
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/findings', methods=['POST'])
def get_findings():
    """Get security findings with filtering and pagination"""
    try:
        data = request.get_json() or {}
        
        filter_dict = data.get('filter', {})
        page_number = data.get('page_number', 1)
        page_size = data.get('page_size', 10)
        sort_by = data.get('sort_by', 'severity')
        sort_order = data.get('sort_order', 'desc')
        search_str = data.get('search_str', '').lower()
        
        filtered_findings = []
        for finding in findings_db:
            if filter_dict:
                match = True
                for key, value in filter_dict.items():
                    if key not in finding or finding[key] != value:
                        match = False
                        break
                if not match:
                    continue
            
            if search_str:
                searchable = f"{finding.get('title', '')} {finding.get('description', '')}".lower()
                if search_str not in searchable:
                    continue
            
            filtered_findings.append(finding)
        
        grouped_findings = {}
        for finding in filtered_findings:
            rule_id = finding['rule_id']
            if rule_id not in grouped_findings:
                grouped_findings[rule_id] = {
                    "rule_id": rule_id,
                    "title": finding['title'],
                    "severity": finding['severity'],
                    "description": finding['description'],
                    "resource_type": finding['resource_type'],
                    "affected_count": 0,
                    "resources_affected": [],
                    "regions_affected": set()
                }
            
            grouped_findings[rule_id]['affected_count'] += 1
            grouped_findings[rule_id]['resources_affected'].append(finding['resource_name'])
            grouped_findings[rule_id]['regions_affected'].add(finding['region'])
        
        issues = []
        for group in grouped_findings.values():
            group['regions_affected'] = list(group['regions_affected'])
            group['resources_affected'] = group['resources_affected'][:10]
            issues.append(group)
        
        reverse = (sort_order == 'desc')
        if sort_by == 'severity':
            severity_order = {'CRITICAL': 4, 'HIGH': 3, 'MEDIUM': 2, 'LOW': 1, 'INFO': 0}
            issues.sort(key=lambda x: severity_order.get(x['severity'], 0), reverse=reverse)
        
        total_count = len(issues)
        total_pages = (total_count + page_size - 1) // page_size
        start_idx = (page_number - 1) * page_size
        end_idx = start_idx + page_size
        paginated_issues = issues[start_idx:end_idx]
        
        return jsonify({
            "current_page": page_number,
            "issues": paginated_issues,
            "total_count": total_count,
            "total_pages": total_pages
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/getSeverityStatus', methods=['GET'])
def get_severity_status():
    """Get count of issues by severity"""
    try:
        severity_counts = defaultdict(int)
        
        for finding in findings_db:
            severity = finding.get('severity', 'INFO')
            severity_counts[severity] += 1
        
        return jsonify({
            "results": {
                "CRITICAL": severity_counts.get('CRITICAL', 0),
                "HIGH": severity_counts.get('HIGH', 0),
                "MEDIUM": severity_counts.get('MEDIUM', 0),
                "LOW": severity_counts.get('LOW', 0),
                "INFO": severity_counts.get('INFO', 0)
            }
        }), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/getIssuesBasedOnResourceTypes', methods=['GET'])
def get_issues_by_resource_type():
    """Get count of issues by resource type"""
    try:
        type_counts = defaultdict(int)
        
        for finding in findings_db:
            resource_type = finding.get('resource_type', 'unknown')
            type_counts[resource_type] += 1
        
        return jsonify({"results": dict(type_counts)}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/getIssuesBasedOnRegions', methods=['GET'])
def get_issues_by_region():
    """Get count of issues by region"""
    try:
        region_counts = defaultdict(int)
        
        for finding in findings_db:
            region = finding.get('region', 'unknown')
            region_counts[region] += 1
        
        return jsonify({"results": dict(region_counts)}), 200
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/loadSampleData', methods=['POST'])
def load_sample_data():
    """Load sample data for testing"""
    sample_resources = [
        {
            "_id": "s3_bucket:111111111111:alpha-public",
            "type": "s3_bucket",
            "cloud": "aws",
            "account_id": "111111111111",
            "name": "alpha-public",
            "region": "us-east-1",
            "tags": {"env": "prod", "owner": "team-a"},
            "public_access": True,
            "versioning": False,
            "encryption": False
        },
        {
            "_id": "ec2_instance:111111111111:web-server-1",
            "type": "ec2_instance",
            "cloud": "aws",
            "account_id": "111111111111",
            "name": "web-server-1",
            "region": "us-east-1",
            "tags": {"env": "prod"},
            "ebs_encrypted": False,
            "os_patch_days": 120
        },
        {
            "_id": "rds_instance:111111111111:prod-db",
            "type": "rds_instance",
            "cloud": "aws",
            "account_id": "111111111111",
            "name": "prod-db",
            "region": "us-west-2",
            "tags": {"env": "prod"},
            "publicly_accessible": True,
            "encryption": True
        }
    ]
    
    sample_rules = [
        {
            "rule_id": "R001",
            "title": "Public S3 bucket",
            "resource_type": "s3_bucket",
            "severity": "HIGH",
            "description": "S3 bucket allows public access.",
            "logic": {"field": "public_access", "op": "eq", "value": True}
        },
        {
            "rule_id": "R002",
            "title": "Unencrypted EC2 EBS Volume",
            "resource_type": "ec2_instance",
            "severity": "HIGH",
            "description": "EC2 instance has an unencrypted EBS volume attached.",
            "logic": {"field": "ebs_encrypted", "op": "eq", "value": False}
        },
        {
            "rule_id": "R004",
            "title": "Outdated EC2 OS Patch",
            "resource_type": "ec2_instance",
            "severity": "MEDIUM",
            "description": "EC2 instance has not been patched for over 90 days.",
            "logic": {"field": "os_patch_days", "op": "gt", "value": 90}
        },
        {
            "rule_id": "R005",
            "title": "RDS Instance Publicly Accessible",
            "resource_type": "rds_instance",
            "severity": "HIGH",
            "description": "RDS instance is publicly accessible from the internet.",
            "logic": {"field": "publicly_accessible", "op": "eq", "value": True}
        }
    ]
    
    for resource in sample_resources:
        severity_score, scanner_reasons = calculate_severity_score(resource)
        resource['severity_score'] = severity_score
        resource['scanner_reasons'] = scanner_reasons
        resource['ingested_at'] = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
        resources_db[resource['_id']] = resource
    
    for rule in sample_rules:
        rules_db[rule['rule_id']] = rule
    
    return jsonify({
        "message": "Sample data loaded successfully",
        "resources_loaded": len(sample_resources),
        "rules_loaded": len(sample_rules)
    }), 200


# ==================== RUN APP ====================

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
