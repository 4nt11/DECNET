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
        """Login with exponential backoff — handles connection storms."""
        for attempt in range(_MAX_LOGIN_RETRIES):
            resp = self.client.post(
                "/api/v1/auth/login",
                json={"username": ADMIN_USER, "password": ADMIN_PASS},
                name="/api/v1/auth/login [on_start]",
            )
            if resp.status_code == 200:
                return resp.json()["access_token"]
            # Status 0 = connection refused, retry with backoff
            if resp.status_code == 0 or resp.status_code >= 500:
                time.sleep(_LOGIN_BACKOFF_BASE * (2 ** attempt))
                continue
            raise RuntimeError(f"Login failed (non-retryable): {resp.status_code} {resp.text}")
        raise RuntimeError(f"Login failed after {_MAX_LOGIN_RETRIES} retries (last status: {resp.status_code})")

    def on_start(self):
        token = self._login_with_retry()

        # Clear must_change_password
        self.client.post(
            "/api/v1/auth/change-password",
            json={"old_password": ADMIN_PASS, "new_password": ADMIN_PASS},
            headers={"Authorization": f"Bearer {token}"},
        )
        # Re-login for a clean token
        self.token = self._login_with_retry()
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

    @task(2)
    def login(self):
        self.client.post(
            "/api/v1/auth/login",
            json={"username": ADMIN_USER, "password": ADMIN_PASS},
        )

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
