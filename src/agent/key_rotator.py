"""Dynamic Gemini API Key Rotation Manager with Round-Robin, OpenClaw Exclusion, and 429 Cooldown."""

import time
import threading
from typing import List, Dict, Any, Tuple, Optional
from google import genai
from src.config import settings


class KeyRotationManager:
    """Enterprise API Key Rotator supporting multi-project quota pools and failover."""

    def __init__(
        self,
        api_keys: Optional[List[str]] = None,
        excluded_suffixes: Optional[List[str]] = None,
        cooldown_seconds: Optional[float] = None
    ):
        self._lock = threading.Lock()
        self.default_cooldown = cooldown_seconds or settings.KEY_COOLDOWN_SECONDS
        
        # 1. Parse excluded suffixes (e.g. OpenClaw keys)
        if excluded_suffixes is not None:
            self.excluded_suffixes = [s.strip() for s in excluded_suffixes if s.strip()]
        else:
            raw_ex = getattr(settings, "EXCLUDED_KEY_SUFFIXES", "0ujA,xqhg")
            self.excluded_suffixes = [s.strip() for s in raw_ex.split(",") if s.strip()]

        # 2. Parse candidate API keys
        raw_keys = api_keys
        if raw_keys is None:
            config_keys = getattr(settings, "GEMINI_API_KEYS", "")
            if config_keys:
                raw_keys = [k.strip() for k in config_keys.split(",") if k.strip()]
            else:
                raw_keys = [settings.GEMINI_API_KEY] if settings.GEMINI_API_KEY else []

        # 3. Filter out excluded keys (e.g., OpenClaw keys)
        self._keys: List[str] = []
        for k in raw_keys:
            k_clean = k.strip()
            if not k_clean:
                continue
            if self._is_excluded(k_clean):
                masked = self.mask_key(k_clean)
                print(f"[KeyRotator] Bỏ qua key '{masked}' vì thuộc danh sách loại trừ của OpenClaw.")
                continue
            if k_clean not in self._keys:
                self._keys.append(k_clean)

        # Fallback if all candidate keys were excluded
        if not self._keys and settings.GEMINI_API_KEY and not self._is_excluded(settings.GEMINI_API_KEY):
            self._keys = [settings.GEMINI_API_KEY]

        # 4. Initialize metadata tracking
        self._key_metadata: Dict[str, Dict[str, Any]] = {}
        self._client_cache: Dict[str, genai.Client] = {}
        for k in self._keys:
            self._key_metadata[k] = {
                "masked_key": self.mask_key(k),
                "cooldown_until": 0.0,
                "total_requests": 0,
                "failed_requests": 0,
            }

        self._current_index = 0
        print(f"[KeyRotator] Đã nạp {len(self._keys)} API Key hợp lệ vào pool xoay vòng (Đã bảo vệ tránh OpenClaw).")

    def _is_excluded(self, api_key: str) -> bool:
        """Check if an API key matches any excluded suffix pattern."""
        for suffix in self.excluded_suffixes:
            if api_key.endswith(suffix):
                return True
        return False

    @staticmethod
    def mask_key(api_key: str) -> str:
        """Safely mask API key for logging purposes."""
        if not api_key or len(api_key) <= 8:
            return "******"
        return f"...{api_key[-4:]}"

    def get_client(self) -> Tuple[genai.Client, str]:
        """Retrieve the next healthy genai.Client and corresponding key via Round-Robin."""
        with self._lock:
            if not self._keys:
                raise RuntimeError("[KeyRotator Lỗi] Không có API Key hợp lệ nào trong hệ thống!")

            now = time.time()
            total_keys = len(self._keys)
            
            # Find the next healthy key (not in cooldown)
            for i in range(total_keys):
                idx = (self._current_index + i) % total_keys
                candidate_key = self._keys[idx]
                meta = self._key_metadata[candidate_key]
                if now >= meta["cooldown_until"]:
                    self._current_index = (idx + 1) % total_keys
                    meta["total_requests"] += 1
                    
                    if candidate_key not in self._client_cache:
                        self._client_cache[candidate_key] = genai.Client(api_key=candidate_key)
                    return self._client_cache[candidate_key], candidate_key

            # If all keys are in cooldown, pick the one that expires earliest
            best_key = min(self._keys, key=lambda k: self._key_metadata[k]["cooldown_until"])
            meta = self._key_metadata[best_key]
            meta["total_requests"] += 1
            print(f"[KeyRotator Cảnh báo] Tất cả các key đều đang trong Cooldown. Sử dụng key '{meta['masked_key']}' sắp hết phạt nhất.")
            
            if best_key not in self._client_cache:
                self._client_cache[best_key] = genai.Client(api_key=best_key)
            return self._client_cache[best_key], best_key

    def mark_exhausted(self, api_key: str, cooldown_seconds: Optional[float] = None, reason: str = "429 Quota Exceeded"):
        """Penalize an API key with cooldown and trigger failover."""
        with self._lock:
            if api_key not in self._key_metadata:
                return
            cooldown = cooldown_seconds if cooldown_seconds is not None else self.default_cooldown
            meta = self._key_metadata[api_key]
            meta["cooldown_until"] = time.time() + cooldown
            meta["failed_requests"] += 1
            print(f"[KeyRotator] ⚠️ Key '{meta['masked_key']}' bị đưa vào Cooldown {cooldown}s. Lý do: {reason}. Tự động chuyển key tiếp theo!")

    def get_stats(self) -> List[Dict[str, Any]]:
        """Return operational telemetry of all keys in rotation."""
        now = time.time()
        stats = []
        with self._lock:
            for k in self._keys:
                meta = self._key_metadata[k]
                stats.append({
                    "masked_key": meta["masked_key"],
                    "is_healthy": now >= meta["cooldown_until"],
                    "cooldown_remaining_sec": max(0.0, round(meta["cooldown_until"] - now, 1)),
                    "total_requests": meta["total_requests"],
                    "failed_requests": meta["failed_requests"]
                })
        return stats


key_rotator = KeyRotationManager()
