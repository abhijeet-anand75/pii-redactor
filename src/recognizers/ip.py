"""
IP Address Recognizer Module for the PII Redaction Tool.

This module provides detection of IP addresses in text.
"""

import re
from typing import List

from src.recognizers.base import BaseRecognizer
from src.models import PII, PIIEntity


class IPRecognizer(BaseRecognizer):
    """
    Recognizer for IP addresses.
    
    Detects both IPv4 and IPv6 addresses using regex pattern matching.
    """
    
    def __init__(self, confidence_threshold: float = 0.85):
        super().__init__(confidence_threshold)
        
        # IPv4 pattern (with private IP detection)
        self._ipv4_pattern = self.compile_pattern(
            r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 pattern (simplified)
        self._ipv6_pattern = self.compile_pattern(
            r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b|'
            r'\b(?:[A-Fa-f0-9]{1,4}:){1,7}:'
        )
    
    @property
    def pii_type(self) -> PII:
        """Get the PII type for this recognizer."""
        return PII.IP_ADDRESS
    
    def _is_private_ip(self, ip: str) -> bool:
        """
        Check if an IP address is private.
        
        Private IP ranges:
        - 10.0.0.0/8
        - 172.16.0.0/12
        - 192.168.0.0/16
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            second = int(parts[1]) if len(parts) > 1 else 0
            
            # Class A private: 10.0.0.0/8
            if first == 10:
                return True
            
            # Class B private: 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True
            
            # Class C private: 192.168.0.0/16
            if first == 192 and second == 168:
                return True
            
            # Loopback: 127.0.0.0/8
            if first == 127:
                return True
            
        except ValueError:
            return False
        
        return False
    
    def _is_reserved_ip(self, ip: str) -> bool:
        """
        Check if an IP address is reserved.
        
        Includes broadcast, documentation, and other reserved ranges.
        """
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        
        try:
            first = int(parts[0])
            
            # Broadcast
            if ip == '255.255.255.255':
                return True
            
            # Documentation and example ranges
            if first == 192 and int(parts[1]) == 0 and int(parts[2]) == 2:
                return True
            if first == 198 and int(parts[1]) == 51 and int(parts[2]) == 100:
                return True
            if first == 203 and int(parts[1]) == 0 and int(parts[2]) == 113:
                return True
            
            # Multicast (224.0.0.0/4)
            if 224 <= first <= 239:
                return True
            
        except ValueError:
            pass
        
        return False
    
    def recognize(self, text: str) -> List[PIIEntity]:
        """
        Recognize IP addresses in the given text.
        
        Args:
            text: The text to scan for IP addresses.
            
        Returns:
            A list of PIIEntity objects for detected IP addresses.
        """
        entities = []
        
        # Detect IPv4 addresses
        matches = self.get_all_matches(text, self._ipv4_pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            ip_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # Calculate confidence
            confidence = 0.90
            
            # Lower confidence for private IPs (less likely to be PII)
            if self._is_private_ip(ip_text):
                confidence = max(0.6, confidence - 0.2)
            
            # Lower confidence for reserved IPs
            if self._is_reserved_ip(ip_text):
                confidence = max(0.4, confidence - 0.3)
                # Skip very obvious reserved IPs
                if confidence < 0.5:
                    continue
            
            # Boost confidence if it's a public IP with normal format
            if not self._is_private_ip(ip_text) and not self._is_reserved_ip(ip_text):
                confidence = min(1.0, confidence + 0.05)
            
            entity = self.create_entity(
                text=ip_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={
                    'version': 'IPv4',
                    'is_private': self._is_private_ip(ip_text)
                }
            )
            
            if entity:
                entities.append(entity)
        
        # Detect IPv6 addresses (higher confidence if found)
        matches = self.get_all_matches(text, self._ipv6_pattern)
        for match in matches:
            if not self.is_valid_match(match, text):
                continue
            
            ip_text = match.group(0)
            start = match.start()
            end = match.end()
            
            # IPv6 is less common, so slightly lower confidence
            confidence = 0.85
            
            # Boost confidence for full IPv6 addresses
            if ':' in ip_text and not ip_text.endswith(':'):
                confidence = min(1.0, confidence + 0.05)
            
            entity = self.create_entity(
                text=ip_text,
                start=start,
                end=end,
                confidence=confidence,
                metadata={'version': 'IPv6'}
            )
            
            if entity:
                entities.append(entity)
        
        return self.filter_entities_by_confidence(entities)