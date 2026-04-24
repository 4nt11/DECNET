"""
Locust user class for DECNET API stress testing.

Hammers every endpoint from the OpenAPI spec with realistic traffic weights.
Can be used standalone (`locust -f tests/stress/locustfile.py`) or
programmatically via the pytest fixtures in conftest.py.
"""

import os
import random
import time

from locust import HttpUser, task, between


ADMIN_USER = os.environ.get("DECNET_ADMIN_USER", "admin")
ADMIN_PASS = os.environ.get("DECNET_ADMIN_PASSWORD", "admin")

_MAX_LOGIN_RETRIES = 5
_LOGIN_BACKOFF_BASE = 0.5  # seconds, doubles each retry


class DecnetUser(HttpUser):
    wait_time = between(0.01, 0.05)  # near-zero think time — max pressure

    def _login_with_retry(self):
        """Login with exponential backoff — handles connection storms
        and (if the server still has rate limits on) 429 throttling.

        Returns (access_token, must_change_password)."""
        for attempt in range(_MAX_LOGIN_RETRIES):
            resp = self.client.post(
                "/api/v1/auth/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS},
                name="/api/v1/auth/login [on_start]",
            )
            if resp.status_code == 200:
                body = resp.json()
                return body["access_token"], bool(body.get("must_change_password", False))
            # Status 0 = connection refused, retry with backoff
            if resp.status_code == 0 or resp.status_code >= 500:
                time.sleep(_LOGIN_BACKOFF_BASE * (2 ** attempt))
                continue
            # 429: the server is rate-limiting logins. In stress runs the
            # fixture sets DECNET_LIMITER_ENABLED=false so we should
            # never see this — but if someone points locust at a real
            # server, honour Retry-After so the run degrades gracefully
            # instead of crashing on_start.
            if resp.status_code == 429:
                retry_after = resp.headers.get("Retry-After")
                delay = _LOGIN_BACKOFF_BASE * (2 ** attempt)
                if retry_after:
                    try:
                        delay = max(delay, float(retry_after))
                    except ValueError:
                        pass
                time.sleep(delay)
                continue
            raise RuntimeError(f"Login failed (non-retryable): {resp.status_code} {resp.text}")
        raise RuntimeError(f"Login failed after {_MAX_LOGIN_RETRIES} retries (last status: {resp.status_code})")

    def on_start(self):
        token, must_change = self._login_with_retry()

        # Only pay the change-password + re-login cost on the very first run
        # against a fresh DB. Every run after that, must_change_password is
        # already False — skip it or the login path becomes a bcrypt storm.
        if must_change:
            self.client.post(
                "/api/v1/auth/change-password",
                json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
                headers={"Authorization": f"Bearer {token}"},
            )
            token, _ = self._login_with_retry()

        self.token = token
        self.client.headers.update({"Authorization": f"Bearer {self.token}"})

    # --- Read-hot paths (high weight) ---

    @task(10)
    def get_stats(self):
        self.client.get("/api/v1/stats")

    @task(8)
    def get_logs(self):
        self.client.get("/api/v1/logs", params={"limit": 50})

    @task(8)
    def get_attackers(self):
        self.client.get("/api/v1/attackers")

    @task(7)
    def get_deckies(self):
        self.client.get("/api/v1/deckies")

    @task(6)
    def get_bounties(self):
        self.client.get("/api/v1/bounty")

    @task(5)
    def get_logs_histogram(self):
        self.client.get("/api/v1/logs/histogram")

    @task(5)
    def search_logs(self):
        self.client.get("/api/v1/logs", params={"search": "ssh", "limit": 100})

    @task(4)
    def search_attackers(self):
        self.client.get(
            "/api/v1/attackers", params={"search": "brute", "sort_by": "recent"}
        )

    @task(4)
    def paginate_logs(self):
        offset = random.randint(0, 1000)
        self.client.get("/api/v1/logs", params={"limit": 100, "offset": offset})

    @task(3)
    def get_health(self):
        self.client.get("/api/v1/health")

    @task(3)
    def get_config(self):
        self.client.get("/api/v1/config")

    # --- Write / auth paths (low weight) ---

    # N.B. a previous revision had a @task(2) login here that re-hit
    # /auth/login during the run. Under N>10 virtual users it burned
    # the 10/5min per-IP + per-username limits and turned the whole
    # stress run into a 429 factory. The login hot path is already
    # covered by on_start for every simulated user; re-logging in on
    # every tick adds no coverage, just contention.

    @task(1)
    def stream_sse(self):
        """Short-lived SSE connection — read a few bytes then close."""
        with self.client.get(
            "/api/v1/stream",
            params={"maxOutput": 3},
            stream=True,
            catch_response=True,
            name="/api/v1/stream",
        ) as resp:
            if resp.status_code == 200:
                # Read up to 4KB then bail — we're stress-testing connection setup
                for chunk in resp.iter_content(chunk_size=1024):
                    break
                resp.success()
            else:
                resp.failure(f"SSE returned {resp.status_code}")
