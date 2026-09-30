"""Small bounded in-memory token bucket for one local server process."""

import asyncio
import time
from collections import deque

from fastapi import Request
from starlette.responses import JSONResponse


class RequestBodyLimit:
    """Reject large JSON bodies, including chunked requests without Content-Length."""

    def __init__(self, app, max_bytes: int = 16384):
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = dict(scope.get("headers", []))
        try:
            length = int(headers.get(b"content-length", b"0"))
        except ValueError:
            length = self.max_bytes + 1
        if length > self.max_bytes:
            await JSONResponse({"detail": "Corpo da requisição muito grande"}, status_code=413)(scope, receive, send)
            return
        size = 0
        chunks = deque()
        deadline = time.monotonic() + 15
        while True:
            try:
                message = await asyncio.wait_for(receive(), timeout=max(0.001, deadline - time.monotonic()))
            except asyncio.TimeoutError:
                await JSONResponse({"detail": "Tempo de envio excedido"}, status_code=408)(scope, receive, send)
                return
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            chunks.append(message)
            if size > self.max_bytes or len(chunks) > 64:
                await JSONResponse({"detail": "Corpo da requisição muito grande"}, status_code=413)(scope, receive, send)
                return
            if not message.get("more_body", False):
                break

        async def replay_receive():
            return chunks.popleft() if chunks else await receive()

        await self.app(scope, replay_receive, send)


class RateLimiter:
    def __init__(self, capacity: int = 60, refill_per_second: float = 1.0):
        self.capacity = capacity
        self.refill = refill_per_second
        self.buckets: dict[str, tuple[float, float]] = {}
        self.lock = asyncio.Lock()

    async def allow(self, key: str, cost: int = 1) -> bool:
        now = time.monotonic()
        async with self.lock:
            # Bound memory even when many distinct source addresses are supplied.
            if len(self.buckets) >= 4096:
                self.buckets = {k: v for k, v in self.buckets.items() if now - v[1] < 120}
                if len(self.buckets) >= 4096 and key not in self.buckets:
                    return False
            tokens, previous = self.buckets.get(key, (float(self.capacity), now))
            tokens = min(float(self.capacity), tokens + (now - previous) * self.refill)
            if tokens < cost:
                self.buckets[key] = (tokens, now)
                return False
            self.buckets[key] = (tokens - cost, now)
            return True


http_limiter = RateLimiter()
login_limiter = RateLimiter(capacity=5, refill_per_second=1 / 30)
ws_limiter = RateLimiter(capacity=20, refill_per_second=2)


async def http_rate_limit(request: Request, call_next):
    ip = request.client.host if request.client else "unknown"
    if not await http_limiter.allow(ip):
        return JSONResponse({"detail": "Limite de requisições excedido"}, status_code=429,
                            headers={"Retry-After": "1"})
    return await call_next(request)
