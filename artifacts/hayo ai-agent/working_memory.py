#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Working Memory System
====================================
Temporary storage for live data with intelligent retrieval,
correlation, and lifecycle management.
"""
import json
import time
import hashlib
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum


class Priority(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MemoryItem:
    key: str
    category: str
    data: Any
    priority: Priority
    timestamp: float
    ttl: Optional[float] = None  # Time to live in seconds
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    @property
    def is_expired(self) -> bool:
        if self.ttl is None:
            return False
        return time.time() - self.timestamp > self.ttl
    
    @property
    def age(self) -> float:
        return time.time() - self.timestamp


class WorkingMemory:
    def __init__(self, default_ttl: float = 3600):
        """
        Initialize working memory system.
        
        Args:
            default_ttl: Default time-to-live for items in seconds (default: 1 hour)
        """
        self.memory: Dict[str, Dict[str, MemoryItem]] = {
            "static_data": {},
            "dynamic_data": {},
            "live_data": {},
            "correlations": {},
            "decisions": {},
            "exploits": {},
            "findings": {},
            "targets": {},
        }
        self.timestamps: Dict[str, float] = {}
        self.default_ttl = default_ttl
        self.access_count: Dict[str, int] = {}
        self._cleanup_interval = 300  # 5 minutes
        self._last_cleanup = time.time()
    
    def _generate_key(self, data: Any) -> str:
        """Generate a unique key for data"""
        if isinstance(data, (str, int, float, bool)):
            return str(data)
        elif isinstance(data, dict):
            return hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
        elif isinstance(data, list):
            return hashlib.md5(json.dumps(data, sort_keys=True).encode()).hexdigest()
        else:
            return str(hash(data))
    
    def add(self, category: str, data: Any, priority: Priority = Priority.MEDIUM, 
            ttl: Optional[float] = None, metadata: Optional[Dict] = None) -> str:
        """
        Add data to memory.
        
        Args:
            category: Category to store data in
            data: Data to store
            priority: Priority level
            ttl: Time-to-live in seconds (None = use default)
            metadata: Additional metadata
        
        Returns:
            Key of the stored item
        """
        if category not in self.memory:
            self.memory[category] = {}
        
        key = self._generate_key(data)
        timestamp = time.time()
        
        item = MemoryItem(
            key=key,
            category=category,
            data=data,
            priority=priority,
            timestamp=timestamp,
            ttl=ttl or self.default_ttl,
            metadata=metadata or {},
        )
        
        self.memory[category][key] = item
        self.timestamps[key] = timestamp
        self.access_count[key] = 0
        
        return key
    
    def get(self, category: str, key: Optional[str] = None, **filters) -> Optional[Any]:
        """
        Retrieve data from memory.
        
        Args:
            category: Category to retrieve from
            key: Specific key to retrieve (None = query)
            **filters: Filter criteria
        
        Returns:
            Retrieved data or None
        """
        self._auto_cleanup()
        
        if category not in self.memory:
            return None
        
        if key:
            item = self.memory[category].get(key)
            if item and not item.is_expired:
                self.access_count[key] = self.access_count.get(key, 0) + 1
                return item.data
            return None
        
        # Query with filters
        results = []
        for item in self.memory[category].values():
            if item.is_expired:
                continue
            if self._match_filters(item, filters):
                self.access_count[item.key] = self.access_count.get(item.key, 0) + 1
                results.append(item.data)
        
        return results if results else None
    
    def query(self, category: str, **criteria) -> List[Any]:
        """
        Advanced query with criteria.
        
        Args:
            category: Category to query
            **criteria: Query criteria
        
        Returns:
            List of matching items
        """
        self._auto_cleanup()
        
        if category not in self.memory:
            return []
        
        results = []
        for item in self.memory[category].values():
            if item.is_expired:
                continue
            if self.__match_criteria(item, criteria):
                self.access_count[item.key] = self.access_count.get(item.key, 0) + 1
                results.append(item.data)
        
        return results
    
    def _match_filters(self, item: MemoryItem, filters: Dict) -> bool:
        """Match item against filters"""
        for key, value in filters.items():
            if key == "priority":
                if item.priority != value:
                    return False
            elif key == "min_age":
                if item.age < value:
                    return False
            elif key == "max_age":
                if item.age > value:
                    return False
            elif key in item.metadata:
                if item.metadata[key] != value:
                    return False
            else:
                # Try to match in data
                if isinstance(item.data, dict):
                    if key not in item.data or item.data[key] != value:
                        return False
                else:
                    return False
        return True
    
    def _match_criteria(self, item: MemoryItem, criteria: Dict) -> bool:
        """Match item against advanced criteria"""
        for key, value in criteria.items():
            if key == "priority":
                if item.priority != value:
                    return False
            elif key == "min_priority":
                if self._priority_value(item.priority) < self._priority_value(value):
                    return False
            elif key == "value_threshold":
                if not self._check_value_threshold(item.data, value):
                    return False
            elif key == "contains":
                if not self._contains(item.data, value):
                    return False
            elif key == "regex":
                import re
                if not re.search(value, str(item.data)):
                    return False
            else:
                if not self._match_filters(item, {key: value}):
                    return False
        return True
    
    def _priority_value(self, priority: Priority) -> int:
        """Convert priority to numeric value"""
        values = {
            Priority.CRITICAL: 4,
            Priority.HIGH: 3,
            Priority.MEDIUM: 2,
            Priority.LOW: 1,
        }
        return values.get(priority, 0)
    
    def _check_value_threshold(self, data: Any, threshold: str) -> bool:
        """Check if data meets value threshold"""
        if threshold == "high":
            return self._is_high_value(data)
        elif threshold == "critical":
            return self._is_critical_value(data)
        return True
    
    def _is_high_value(self, data: Any) -> bool:
        """Check if data is high value"""
        if isinstance(data, dict):
            # Check for sensitive keys
            sensitive_keys = ["key", "secret", "token", "password", "credential"]
            return any(k in data for k in sensitive_keys)
        elif isinstance(data, str):
            # Check for patterns
            import re
            patterns = [
                r"AKIA[0-9A-Z]{16}",  # AWS key
                r"sk_live_[A-Za-z0-9]{24,}",  # Stripe key
                r"AIza[0-9A-Za-z_-]{35}",  # Google API key
            ]
            return any(re.search(p, data) for p in patterns)
        return False
    
    def _is_critical_value(self, data: Any) -> bool:
        """Check if data is critical value"""
        if isinstance(data, dict):
            # Check for critical keys
            critical_keys = ["aws_secret", "stripe_sk", "private_key", "mnemonic"]
            return any(k in data for k in critical_keys)
        return False
    
    def _contains(self, data: Any, value: str) -> bool:
        """Check if data contains value"""
        return value.lower() in str(data).lower()
    
    def correlate(self, source_category: str, target_category: str, 
                  correlation_fn: Optional[Callable] = None) -> List[Dict]:
        """
        Correlate data between two categories.
        
        Args:
            source_category: Source category
            target_category: Target category
            correlation_fn: Custom correlation function (optional)
        
        Returns:
            List of correlations with confidence scores
        """
        self._auto_cleanup()
        
        if source_category not in self.memory or target_category not in self.memory:
            return []
        
        correlations = []
        source_items = [item for item in self.memory[source_category].values() if not item.is_expired]
        target_items = [item for item in self.memory[target_category].values() if not item.is_expired]
        
        for source_item in source_items:
            for target_item in target_items:
                if correlation_fn:
                    confidence = correlation_fn(source_item.data, target_item.data)
                else:
                    confidence = self._calculate_confidence(source_item.data, target_item.data)
                
                if confidence > 0.5:  # Only keep high-confidence correlations
                    correlation = {
                        "source": {
                            "category": source_category,
                            "key": source_item.key,
                            "data": source_item.data,
                        },
                        "target": {
                            "category": target_category,
                            "key": target_item.key,
                            "data": target_item.data,
                        },
                        "confidence": confidence,
                        "timestamp": time.time(),
                    }
                    correlations.append(correlation)
                    
                    # Store correlation in memory
                    self.add("correlations", correlation, Priority.HIGH)
        
        return correlations
    
    def _calculate_confidence(self, source_data: Any, target_data: Any) -> float:
        """Calculate correlation confidence between two data items"""
        confidence = 0.0
        
        # String matching
        if isinstance(source_data, str) and isinstance(target_data, str):
            if source_data.lower() == target_data.lower():
                confidence = 1.0
            elif source_data.lower() in target_data.lower() or target_data.lower() in source_data.lower():
                confidence = 0.8
            else:
                # Levenshtein distance approximation
                common = set(source_data.lower()) & set(target_data.lower())
                confidence = len(common) / max(len(set(source_data)), len(set(target_data)))
        
        # Dict matching
        elif isinstance(source_data, dict) and isinstance(target_data, dict):
            common_keys = set(source_data.keys()) & set(target_data.keys())
            if common_keys:
                matching_values = sum(
                    1 for k in common_keys 
                    if source_data[k] == target_data[k]
                )
                confidence = matching_values / len(common_keys)
        
        # List matching
        elif isinstance(source_data, list) and isinstance(target_data, list):
            common = set(source_data) & set(target_data)
            if common:
                confidence = len(common) / max(len(set(source_data)), len(set(target_data)))
        
        return confidence
    
    def get_high_value_data(self, category: str, min_priority: Priority = Priority.HIGH) -> List[Any]:
        """
        Get high-value data from a category.
        
        Args:
            category: Category to retrieve from
            min_priority: Minimum priority level
        
        Returns:
            List of high-value items
        """
        self._auto_cleanup()
        
        if category not in self.memory:
            return []
        
        results = []
        for item in self.memory[category].values():
            if item.is_expired:
                continue
            if self._priority_value(item.priority) >= self._priority_value(min_priority):
                self.access_count[item.key] = self.access_count.get(item.key, 0) + 1
                results.append(item.data)
        
        # Sort by priority (highest first)
        results.sort(key=lambda x: self._priority_value(
            next(item.priority for item in self.memory[category].values() if item.data == x)
        ), reverse=True)
        
        return results
    
    def get_all(self) -> Dict[str, List[Any]]:
        """Get all data from memory (grouped by category)"""
        self._auto_cleanup()
        
        result = {}
        for category, items in self.memory.items():
            result[category] = [
                item.data for item in items.values() if not item.is_expired
            ]
        
        return result
    
    def update(self, category: str, key: str, data: Any, 
               priority: Optional[Priority] = None, metadata: Optional[Dict] = None):
        """Update an existing item"""
        if category not in self.memory or key not in self.memory[category]:
            return
        
        item = self.memory[category][key]
        item.data = data
        item.timestamp = time.time()
        if priority:
            item.priority = priority
        if metadata:
            item.metadata.update(metadata)
    
    def remove(self, category: str, key: str):
        """Remove an item from memory"""
        if category in self.memory and key in self.memory[category]:
            del self.memory[category][key]
            if key in self.timestamps:
                del self.timestamps[key]
            if key in self.access_count:
                del self.access_count[key]
    
    def cleanup(self, max_age: Optional[float] = None):
        """
        Clean up expired or old items.
        
        Args:
            max_age: Maximum age in seconds (None = use default TTL)
        """
        now = time.time()
        max_age = max_age or self.default_ttl
        
        for category in list(self.memory.keys()):
            for key in list(self.memory[category].keys()):
                item = self.memory[category][key]
                if item.is_expired or (now - item.timestamp > max_age):
                    self.remove(category, key)
    
    def _auto_cleanup(self):
        """Automatic cleanup based on interval"""
        now = time.time()
        if now - self._last_cleanup > self._cleanup_interval:
            self.cleanup()
            self._last_cleanup = now
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics"""
        total_items = sum(len(items) for items in self.memory.values())
        expired_items = sum(
            1 for items in self.memory.values()
            for item in items.values()
            if item.is_expired
        )
        
        category_stats = {}
        for category, items in self.memory.items():
            category_stats[category] = {
                "total": len(items),
                "expired": sum(1 for item in items.values() if item.is_expired),
                "by_priority": {
                    "critical": sum(1 for item in items.values() if item.priority == Priority.CRITICAL),
                    "high": sum(1 for item in items.values() if item.priority == Priority.HIGH),
                    "medium": sum(1 for item in items.values() if item.priority == Priority.MEDIUM),
                    "low": sum(1 for item in items.values() if item.priority == Priority.LOW),
                }
            }
        
        return {
            "total_items": total_items,
            "expired_items": expired_items,
            "active_items": total_items - expired_items,
            "categories": category_stats,
            "cleanup_interval": self._cleanup_interval,
            "default_ttl": self.default_ttl,
        }
    
    def export(self) -> Dict:
        """Export memory to serializable format"""
        export_data = {}
        for category, items in self.memory.items():
            export_data[category] = []
            for item in items.values():
                export_data[category].append({
                    "key": item.key,
                    "data": item.data,
                    "priority": item.priority.value,
                    "timestamp": item.timestamp,
                    "ttl": item.ttl,
                    "metadata": item.metadata,
                })
        
        return {
            "memory": export_data,
            "timestamps": self.timestamps,
            "access_count": self.access_count,
            "stats": self.get_stats(),
            "exported_at": time.time(),
        }
    
    def import_data(self, data: Dict):
        """Import memory from serializable format"""
        if "memory" not in data:
            return
        
        for category, items in data["memory"].items():
            if category not in self.memory:
                self.memory[category] = {}
            
            for item_data in items:
                item = MemoryItem(
                    key=item_data["key"],
                    category=category,
                    data=item_data["data"],
                    priority=Priority(item_data["priority"]),
                    timestamp=item_data["timestamp"],
                    ttl=item_data.get("ttl"),
                    metadata=item_data.get("metadata", {}),
                )
                self.memory[category][item.key] = item
        
        if "timestamps" in data:
            self.timestamps.update(data["timestamps"])
        
        if "access_count" in data:
            self.access_count.update(data["access_count"])


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يملأ الذاكرة من نتائج جلسة ديناميكية حقيقية ويطبع
    # إحصاءات/بيانات عالية القيمة فعلية — لا بيانات ديمو.
    from standalone_utils import parse_target_args, require_session

    # ملاحظة: نستخدم Priority المحلية (وحدة __main__) لا standalone_utils.severity_to_priority،
    # لأن الأخيرة تُعيد استيراد working_memory كوحدة منفصلة فيختلف كائن Priority وتفشل المقارنة.
    def _sev(sev):
        return {"critical": Priority.CRITICAL, "high": Priority.HIGH,
                "medium": Priority.MEDIUM, "low": Priority.LOW}.get(str(sev).lower(), Priority.MEDIUM)

    args = parse_target_args("Working Memory — عرض ذاكرة العمل من جلسة حقيقية")
    _path, session = require_session(args.package, args.session)

    memory = WorkingMemory()
    findings = session.get("findings", [])
    triaged = session.get("triaged", [])
    for f in findings:
        cat = str(f.get("type", "finding")).split(".")[0] or "finding"
        memory.add(cat, f, _sev(f.get("severity")))
    for t in triaged:
        memory.add("triaged", t, _sev(t.get("severity")))

    print(f"\n[+] حُمّلت {len(findings)} نتيجة خام + {len(triaged)} مُصنّفة إلى الذاكرة.")

    hv = memory.get_high_value_data("triaged")
    print(f"\n[*] بيانات عالية القيمة (triaged, ≥HIGH): {len(hv)}")
    for item in hv[:10]:
        d = item if isinstance(item, dict) else getattr(item, "data", {})
        print(f"    - [{d.get('severity','?')}] {d.get('type','?')}: "
              f"{str(d.get('title') or d.get('detail') or '')[:70]}")

    stats = memory.get_stats()
    print(f"\n[*] إحصاءات الذاكرة:\n{json.dumps(stats, ensure_ascii=False, indent=2)}")
