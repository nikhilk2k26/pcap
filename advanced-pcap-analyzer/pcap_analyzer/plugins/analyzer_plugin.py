#!/usr/bin/env python3
"""
Plugin System for Analyzers

Provides base class for analyzer plugins.
"""

from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional

from pcap_analyzer.models.finding import Finding


class AnalyzerPlugin(ABC):
    """
    Base class for analyzer plugins.
    
    Plugins can be created to add support for new protocols,
    custom detection rules, or specialized analysis.
    """
    
    # Plugin metadata
    name: str = "base_plugin"
    description: str = "Base analyzer plugin"
    version: str = "1.0.0"
    supported_protocols: List[str] = []
    
    def __init__(self, config=None):
        self.config = config
        self.findings: List[Finding] = []
        self.metrics: Dict[str, Any] = {}
    
    @abstractmethod
    def analyze(self, packet_index, context: Optional[Dict] = None) -> Any:
        """
        Perform analysis on packet data.
        
        Args:
            packet_index: Access to packet storage/index
            context: Additional context information
            
        Returns:
            Analysis result specific to the plugin
        """
        pass
    
    @abstractmethod
    def generate_findings(self) -> List[Finding]:
        """
        Generate findings from analysis results.
        
        Returns:
            List of Finding objects
        """
        pass
    
    @abstractmethod
    def generate_metrics(self) -> Dict[str, Any]:
        """
        Generate metrics from analysis.
        
        Returns:
            Dictionary of metric names to values
        """
        pass
    
    def is_supported(self, protocol: str) -> bool:
        """Check if this plugin supports a given protocol."""
        return protocol in self.supported_protocols
    
    def get_info(self) -> Dict[str, Any]:
        """Get plugin information."""
        return {
            'name': self.name,
            'description': self.description,
            'version': self.version,
            'supported_protocols': self.supported_protocols,
        }


class PluginManager:
    """
    Manages analyzer plugins.
    """
    
    def __init__(self):
        self.plugins: Dict[str, AnalyzerPlugin] = {}
    
    def register(self, plugin: AnalyzerPlugin):
        """Register a plugin."""
        self.plugins[plugin.name] = plugin
    
    def unregister(self, name: str):
        """Unregister a plugin by name."""
        if name in self.plugins:
            del self.plugins[name]
    
    def get_plugin(self, name: str) -> Optional[AnalyzerPlugin]:
        """Get a plugin by name."""
        return self.plugins.get(name)
    
    def get_plugins_for_protocol(self, protocol: str) -> List[AnalyzerPlugin]:
        """Get all plugins that support a given protocol."""
        return [p for p in self.plugins.values() if p.is_supported(protocol)]
    
    def run_analysis(self, packet_index, protocol: str, context: Optional[Dict] = None) -> Dict:
        """
        Run all plugins for a given protocol.
        
        Args:
            packet_index: Access to packet data
            protocol: Protocol to analyze
            context: Additional context
            
        Returns:
            Dictionary with findings and metrics from all plugins
        """
        results = {
            'findings': [],
            'metrics': {},
            'plugins_used': [],
        }
        
        for plugin in self.get_plugins_for_protocol(protocol):
            try:
                analysis_result = plugin.analyze(packet_index, context)
                findings = plugin.generate_findings()
                metrics = plugin.generate_metrics()
                
                results['findings'].extend(findings)
                results['metrics'].update(metrics)
                results['plugins_used'].append(plugin.name)
                
            except Exception as e:
                results['metrics'][f'{plugin.name}_error'] = str(e)
        
        return results
    
    def list_plugins(self) -> List[Dict]:
        """List all registered plugins."""
        return [p.get_info() for p in self.plugins.values()]
