#!/usr/bin/env python3
"""
JSON Report Generator

Generates machine-readable JSON reports.
"""

import json
from typing import Optional, List, Dict, Any

from config import Config


class JSONReportGenerator:
    """
    Generates JSON reports for machine consumption.
    """
    
    def __init__(self, config: Optional[Config] = None):
        self.config = config or Config()
    
    def generate(
        self,
        summary=None,
        tcp_analysis=None,
        dns_analysis=None,
        latency_analysis=None,
        findings=None,
    ) -> str:
        """Generate full JSON report."""
        report = {
            'report_type': 'full_analysis',
            'summary': summary.to_dict() if summary else None,
            'tcp_analysis': tcp_analysis.to_dict() if tcp_analysis else None,
            'dns_analysis': dns_analysis.to_dict() if dns_analysis else None,
            'latency_analysis': latency_analysis.to_dict() if latency_analysis else None,
            'findings': [f.to_dict() for f in (findings or [])],
        }
        
        return json.dumps(report, indent=self.config.report.json_indent)
    
    def generate_findings_json(self, findings) -> str:
        """Generate JSON with only findings."""
        return json.dumps({
            'findings': [f.to_dict() for f in findings],
        }, indent=self.config.report.json_indent)
    
    def generate_flows_json(self, flows) -> str:
        """Generate JSON with flow records."""
        return json.dumps({
            'flows': [f.to_dict() for f in flows],
        }, indent=self.config.report.json_indent)
