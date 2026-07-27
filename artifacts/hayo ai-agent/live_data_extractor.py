#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HAYO Cipher-7 — Live Data Extraction Engine
===========================================
Extracts and processes live data from the application in real-time,
passing it to the AI brain for immediate analysis.
"""
import json
import re
import time
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod


class DataType(Enum):
    CRYPTO = "crypto"
    NETWORK = "network"
    STORAGE = "storage"
    MEMORY = "memory"
    BIOMETRIC = "biometric"
    LOCATION = "location"
    CAMERA = "camera"
    AUDIO = "audio"
    SENSOR = "sensor"
    NOTIFICATION = "notification"
    PERMISSION = "permission"
    DATABASE = "database"
    WEBVIEW = "webview"
    IPC = "ipc"
    RUNTIME = "runtime"
    LOGGING = "logging"


@dataclass
class ExtractedData:
    type: DataType
    data: Dict[str, Any]
    priority: str
    timestamp: float
    source: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class DataExtractor(ABC):
    """Base class for data extractors"""
    
    @abstractmethod
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        """Extract data from Frida message"""
        pass
    
    @abstractmethod
    def get_data_type(self) -> DataType:
        """Get the data type this extractor handles"""
        pass


class CryptoExtractor(DataExtractor):
    """Extracts cryptographic data"""
    
    def get_data_type(self) -> DataType:
        return DataType.CRYPTO
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["crypto_key", "crypto_iv", "crypto_algorithm", "ssl_pinning"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "critical" if "key" in frida_message.get("type", "") else "high"
        
        return ExtractedData(
            type=DataType.CRYPTO,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "class": frida_message.get("class"),
                "method": frida_message.get("method"),
            }
        )


class NetworkExtractor(DataExtractor):
    """Extracts network data"""
    
    def get_data_type(self) -> DataType:
        return DataType.NETWORK
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["http_request", "http_response", "websocket", "ssl_handshake"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "high"
        
        # Check for sensitive data in headers/body
        headers = data.get("headers", {})
        body = data.get("body", "")
        
        sensitive_patterns = ["authorization", "token", "key", "secret", "password"]
        for pattern in sensitive_patterns:
            if any(pattern in str(k).lower() for k in headers.keys()) or pattern in body.lower():
                priority = "critical"
                break
        
        return ExtractedData(
            type=DataType.NETWORK,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "url": data.get("url"),
                "method": data.get("method"),
            }
        )


class StorageExtractor(DataExtractor):
    """Extracts storage data"""
    
    def get_data_type(self) -> DataType:
        return DataType.STORAGE
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["shared_prefs", "sqlite_query", "file_read", "file_write"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "high"
        
        # Check for sensitive keys
        keys = data.get("keys", [])
        query = data.get("query", "")
        
        sensitive_patterns = ["token", "password", "secret", "key", "credential"]
        for pattern in sensitive_patterns:
            if any(pattern in str(k).lower() for k in keys) or pattern in query.lower():
                priority = "critical"
                break
        
        return ExtractedData(
            type=DataType.STORAGE,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "path": data.get("path"),
            }
        )


class MemoryExtractor(DataExtractor):
    """Extracts memory data"""
    
    def get_data_type(self) -> DataType:
        return DataType.MEMORY
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["memory_scavenge", "heap_scan", "string_dump"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "medium"
        
        # Check for sensitive strings
        strings = data.get("strings", [])
        sensitive_patterns = [
            r"AKIA[0-9A-Z]{16}",  # AWS key
            r"sk_live_[A-Za-z0-9]{24,}",  # Stripe key
            r"AIza[0-9A-Za-z_-]{35}",  # Google API key
        ]
        
        for s in strings:
            for pattern in sensitive_patterns:
                if re.search(pattern, s):
                    priority = "critical"
                    break
            if priority == "critical":
                break
        
        return ExtractedData(
            type=DataType.MEMORY,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "address": data.get("address"),
            }
        )


class BiometricExtractor(DataExtractor):
    """Extracts biometric data"""
    
    def get_data_type(self) -> DataType:
        return DataType.BIOMETRIC
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["biometric_auth", "fingerprint", "face_auth"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "high"
        
        return ExtractedData(
            type=DataType.BIOMETRIC,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "result": data.get("result"),
            }
        )


class LocationExtractor(DataExtractor):
    """Extracts location data"""
    
    def get_data_type(self) -> DataType:
        return DataType.LOCATION
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["location_update", "gps_coordinates"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "medium"
        
        return ExtractedData(
            type=DataType.LOCATION,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "provider": data.get("provider"),
            }
        )


class WebViewExtractor(DataExtractor):
    """Extracts WebView data"""
    
    def get_data_type(self) -> DataType:
        return DataType.WEBVIEW
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["webview_load", "js_interface", "webview_eval"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "medium"
        
        # Check for sensitive data in URL or JS
        url = data.get("url", "")
        js_code = data.get("js_code", "")
        
        if "token" in url.lower() or "key" in url.lower():
            priority = "high"
        
        return ExtractedData(
            type=DataType.WEBVIEW,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "url": url,
            }
        )


class IPCExtractor(DataExtractor):
    """Extracts IPC data"""
    
    def get_data_type(self) -> DataType:
        return DataType.IPC
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        if frida_message.get("type") not in ["intent_send", "binder_call", "content_provider_query"]:
            return None
        
        data = frida_message.get("data", {})
        priority = "medium"
        
        return ExtractedData(
            type=DataType.IPC,
            data=data,
            priority=priority,
            timestamp=time.time(),
            source="frida",
            metadata={
                "hook_type": frida_message.get("type"),
                "action": data.get("action"),
                "component": data.get("component"),
            }
        )


class LiveDataExtractor:
    def __init__(self, context):
        """
        Initialize the live data extractor.
        
        Args:
            context: Working memory context
        """
        self.context = context
        self.extractors: Dict[DataType, DataExtractor] = {}
        self._initialize_extractors()
        self.extraction_stats = {
            "total_extracted": 0,
            "by_type": {},
            "by_priority": {},
        }
    
    def _initialize_extractors(self):
        """Initialize all data extractors"""
        extractors = [
            CryptoExtractor(),
            NetworkExtractor(),
            StorageExtractor(),
            MemoryExtractor(),
            BiometricExtractor(),
            LocationExtractor(),
            WebViewExtractor(),
            IPCExtractor(),
        ]
        
        for extractor in extractors:
            self.extractors[extractor.get_data_type()] = extractor
    
    def add_custom_extractor(self, extractor: DataExtractor):
        """Add a custom data extractor"""
        self.extractors[extractor.get_data_type()] = extractor
    
    def extract(self, frida_message: Dict) -> Optional[ExtractedData]:
        """
        Extract data from a Frida message.
        
        Args:
            frida_message: Message from Frida
        
        Returns:
            ExtractedData or None
        """
        for extractor in self.extractors.values():
            try:
                extracted = extractor.extract(frida_message)
                if extracted:
                    # Add to context
                    self.context.add(
                        category="live_data",
                        data=extracted.data,
                        priority=self._convert_priority(extracted.priority),
                        metadata={
                            "type": extracted.type.value,
                            "source": extracted.source,
                            "timestamp": extracted.timestamp,
                            **extracted.metadata,
                        }
                    )
                    
                    # Update stats
                    self.extraction_stats["total_extracted"] += 1
                    dtype = extracted.type.value
                    self.extraction_stats["by_type"][dtype] = self.extraction_stats["by_type"].get(dtype, 0) + 1
                    self.extraction_stats["by_priority"][extracted.priority] = self.extraction_stats["by_priority"].get(extracted.priority, 0) + 1
                    
                    return extracted
            except Exception as e:
                print(f"[!] Extraction failed: {e}")
        
        return None
    
    def _convert_priority(self, priority_str: str):
        """Convert string priority to Priority enum"""
        from working_memory import Priority
        priority_map = {
            "critical": Priority.CRITICAL,
            "high": Priority.HIGH,
            "medium": Priority.MEDIUM,
            "low": Priority.LOW,
        }
        return priority_map.get(priority_str.lower(), Priority.MEDIUM)
    
    def extract_batch(self, frida_messages: List[Dict]) -> List[ExtractedData]:
        """
        Extract data from multiple Frida messages.
        
        Args:
            frida_messages: List of Frida messages
        
        Returns:
            List of extracted data
        """
        results = []
        for message in frida_messages:
            extracted = self.extract(message)
            if extracted:
                results.append(extracted)
        return results
    
    def get_high_value_data(self) -> List[Dict]:
        """Get high-value extracted data"""
        return self.context.get_high_value_data("live_data")
    
    def get_data_by_type(self, data_type: DataType) -> List[Dict]:
        """Get extracted data by type"""
        return self.context.query("live_data", type=data_type.value)
    
    def get_stats(self) -> Dict:
        """Get extraction statistics"""
        return self.extraction_stats
    
    def reset_stats(self):
        """Reset extraction statistics"""
        self.extraction_stats = {
            "total_extracted": 0,
            "by_type": {},
            "by_priority": {},
        }


if __name__ == "__main__":
    # تشغيل منفصل حقيقي: يعيد تمرير النتائج الملتقطة في جلسة حقيقية عبر المستخلِص
    # ويطبع ما استُخلص فعلاً. الاستخلاص الحيّ الكامل يجري داخل المسار أثناء التشغيل؛
    # هنا نعرض المُستخلَص من الجلسة الفعلية — لا رسائل ديمو.
    from working_memory import WorkingMemory
    from standalone_utils import parse_target_args, require_session

    args = parse_target_args("Live Data Extraction — استخلاص من جلسة حقيقية")
    _path, session = require_session(args.package, args.session)

    memory = WorkingMemory()
    extractor = LiveDataExtractor(memory)

    def _to_frida_message(f):
        """يحوّل finding حقيقي إلى شكل رسالة frida يفهمه المستخلِص، إن أمكن."""
        ftype = str(f.get("type", "")).lower()
        ev = f.get("evidence", {})
        ev = ev if isinstance(ev, dict) else {"value": ev}
        if any(k in ftype for k in ("http", "url", "network", "request", "api")) or ev.get("url"):
            return {"type": "http_request", "data": {
                "url": ev.get("url", ""), "method": ev.get("method", "GET"),
                "headers": ev.get("headers", {}), "body": ev.get("body", "")}}
        if any(k in ftype for k in ("crypto", "key", "secret", "token", "jwt")):
            return {"type": "crypto_key", "data": ev,
                    "class": ev.get("class"), "method": ev.get("method")}
        if any(k in ftype for k in ("pref", "sqlite", "file", "storage")):
            return {"type": "shared_prefs", "data": ev}
        return None

    findings = session.get("findings", [])
    extracted_count = 0
    for f in findings:
        msg = _to_frida_message(f)
        if not msg:
            continue
        item = extractor.extract(msg)
        if item:
            extracted_count += 1
            print(f"    ✔ {item.type.value:14s} [{item.priority}]  "
                  f"{str(f.get('type','?'))[:40]}")

    print(f"\n[+] مرّرنا {len(findings)} نتيجة → استُخلص منها {extracted_count} عنصراً حقيقياً.")
    if extracted_count == 0:
        print("    (لم تتطابق نتائج الجلسة مع أنواع الاستخلاص الحيّ — شغّل المحرّك")
        print("     الديناميكي لالتقاط بيانات حيّة أغنى.)")
    stats = extractor.get_stats()
    print(f"\n[*] إحصاءات الاستخلاص:\n{json.dumps(stats, ensure_ascii=False, indent=2)}")
