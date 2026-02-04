#!/usr/bin/env python3
"""
Update LogicMonitor device custom properties from a CSV file.

What it does
------------
For each row in the CSV, this script will:
1) Check whether the target device already has the given custom property.
2) If it exists, update its value (PUT).
3) If it does not exist, add it (POST).

CSV format
----------
Required header columns (case-sensitive):
    ID,Name,Property,Value

Example:
    ID,Name,Property,Value
    10,myDevice,snmp.community,public

Notes:
- The "Name" column is informational only (used for logging); the script keys off "ID".
- Properties are checked by name. If a property exists but with different case, the script
  will update using the canonical name returned by the API.

Security
--------
Avoid hardcoding credentials in the file. Prefer environment variables:
    LM_COMPANY, LM_ACCESS_ID, LM_ACCESS_KEY

Usage
--------
python3 update_resource_properties_from_csv_v2.py \
  --company yourcompany \
  --access-id xxxx \
  --access-key yyyy \
  --csv device_list-5-prod.csv

Or pass them via CLI flags (see --help).

Other flags
-----------
--dry-run Does not apply, just reports what WOULD have occured.



Script exit codes
-----------------
0  success
2  input/validation error
3  API error (after retries)

"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import hmac
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

import requests


LOG = logging.getLogger("lm_csv_property_updater")


@dataclass(frozen=True)
class LMConfig:
    company: str
    access_id: str
    access_key: str
    timeout_s: int = 30
    max_retries: int = 5
    backoff_base_s: float = 0.75


class LMAPIError(RuntimeError):
    """Raised when the LogicMonitor API request fails after retries."""


def _now_ms() -> str:
    return str(int(time.time() * 1000))


def _sign_lmv1(access_id: str, access_key: str, http_verb: str, epoch_ms: str, data: str, resource_path: str) -> str:
    """
    Build LMv1 Authorization header value.

    LM signature format (conceptually):
        signature = base64encode( HMAC_SHA256(access_key, httpVerb + epoch + data + resourcePath).hexdigest() )
    """
    request_vars = f"{http_verb}{epoch_ms}{data}{resource_path}"
    digest_hex = hmac.new(access_key.encode("utf-8"), msg=request_vars.encode("utf-8"), digestmod=hashlib.sha256).hexdigest()
    signature = base64.b64encode(digest_hex.encode("utf-8")).decode("utf-8")
    return f"LMv1 {access_id}:{signature}:{epoch_ms}"


def _request(
    cfg: LMConfig,
    session: requests.Session,
    http_verb: str,
    resource_path: str,
    query: str = "",
    json_body: Optional[Dict[str, Any]] = None,
) -> requests.Response:
    """
    Make a signed LogicMonitor REST request with retry/backoff for transient errors.

    Retries on:
    - 429 Too Many Requests
    - 5xx server errors
    - transient network errors (requests exceptions)
    """
    if not resource_path.startswith("/"):
        raise ValueError("resource_path must start with '/'")

    url = f"https://{cfg.company}.logicmonitor.com/santaba/rest{resource_path}{query}"
    data_str = "" if json_body is None else json.dumps(json_body, separators=(",", ":"))

    for attempt in range(1, cfg.max_retries + 1):
        epoch = _now_ms()
        auth = _sign_lmv1(cfg.access_id, cfg.access_key, http_verb, epoch, data_str, resource_path)
        headers = {"Content-Type": "application/json", "Authorization": auth}

        try:
            resp = session.request(
                method=http_verb,
                url=url,
                headers=headers,
                data=data_str if data_str else None,
                timeout=cfg.timeout_s,
            )
        except requests.RequestException as e:
            if attempt >= cfg.max_retries:
                raise LMAPIError(f"Network error after {attempt} attempts: {e}") from e
            sleep_s = cfg.backoff_base_s * (2 ** (attempt - 1))
            LOG.warning("Network error (%s). Retry %d/%d in %.2fs", e, attempt, cfg.max_retries, sleep_s)
            time.sleep(sleep_s)
            continue

        if resp.status_code in (429, 500, 502, 503, 504):
            if attempt >= cfg.max_retries:
                break
            # Use Retry-After when present, else exponential backoff
            retry_after = resp.headers.get("Retry-After")
            if retry_after:
                try:
                    sleep_s = float(retry_after)
                except ValueError:
                    sleep_s = cfg.backoff_base_s * (2 ** (attempt - 1))
            else:
                sleep_s = cfg.backoff_base_s * (2 ** (attempt - 1))
            LOG.warning("HTTP %s from API. Retry %d/%d in %.2fs. URL=%s", resp.status_code, attempt, cfg.max_retries, sleep_s, url)
            time.sleep(sleep_s)
            continue

        return resp

    # If we get here, retries exhausted for HTTP status codes
    body_preview = ""
    try:
        body_preview = resp.text[:2000]
    except Exception:
        body_preview = "<unable to read response body>"
    raise LMAPIError(f"API request failed after {cfg.max_retries} attempts: HTTP {resp.status_code}. Body (preview): {body_preview}")


def get_device_property(cfg: LMConfig, session: requests.Session, device_id: str, prop_name: str) -> Tuple[int, Optional[str]]:
    """
    Query a device for a specific property.

    Returns:
        (total, canonical_name)
        - total: number of matching property items (0 means not present)
        - canonical_name: exact property name as returned by LM (preserves case) if present, else None
    """
    resource_path = f"/device/devices/{device_id}/properties"
    query = f"?filter=name:{prop_name}"
    resp = _request(cfg, session, "GET", resource_path, query=query)

    if resp.status_code != 200:
        raise LMAPIError(f"GET properties failed for device {device_id}: HTTP {resp.status_code} {resp.text}")

    payload = resp.json()
    data = payload.get("data")
    if not data:
        # Some API errors come back with data = None and errmsg present
        errmsg = payload.get("errmsg") or "Unknown error"
        raise LMAPIError(f"GET properties returned no data for device {device_id}: {errmsg}")

    total = int(data.get("total", 0))
    if total <= 0:
        return 0, None

    items = data.get("items") or []
    canonical = items[0].get("name") if items else None
    return total, canonical


def add_device_property(cfg: LMConfig, session: requests.Session, device_id: str, prop_name: str, value: str, dry_run: bool) -> None:
    resource_path = f"/device/devices/{device_id}/properties"
    body = {"name": prop_name, "value": value}

    if dry_run:
        LOG.info("DRY-RUN add: device=%s property=%s value=%s", device_id, prop_name, value)
        return

    resp = _request(cfg, session, "POST", resource_path, json_body=body)
    if resp.status_code not in (200, 201):
        raise LMAPIError(f"POST add property failed for device {device_id} property {prop_name}: HTTP {resp.status_code} {resp.text}")

    LOG.info("Added:   device=%s property=%s value=%s", device_id, prop_name, value)


def update_device_property(cfg: LMConfig, session: requests.Session, device_id: str, prop_name: str, value: str, dry_run: bool) -> None:
    resource_path = f"/device/devices/{device_id}/properties/{prop_name}"
    body = {"value": value}

    if dry_run:
        LOG.info("DRY-RUN update: device=%s property=%s value=%s", device_id, prop_name, value)
        return

    resp = _request(cfg, session, "PUT", resource_path, json_body=body)
    if resp.status_code != 200:
        raise LMAPIError(f"PUT update property failed for device {device_id} property {prop_name}: HTTP {resp.status_code} {resp.text}")

    LOG.info("Updated: device=%s property=%s value=%s", device_id, prop_name, value)


def upsert_property(cfg: LMConfig, session: requests.Session, device_id: str, prop_name: str, value: str, dry_run: bool) -> None:
    total, canonical_name = get_device_property(cfg, session, device_id, prop_name)
    if total == 0:
        add_device_property(cfg, session, device_id, prop_name, value, dry_run=dry_run)
    else:
        # Use canonical case returned by LM if available
        update_device_property(cfg, session, device_id, canonical_name or prop_name, value, dry_run=dry_run)


def _require_env_or_arg(arg_val: Optional[str], env_name: str, human_name: str) -> str:
    val = arg_val or os.getenv(env_name)
    if not val:
        raise ValueError(f"Missing {human_name}. Provide --{human_name.lower().replace(' ', '-')} or set {env_name}.")
    return val


def _validate_csv_header(fieldnames: Optional[list[str]]) -> None:
    required = {"ID", "Name", "Property", "Value"}
    if not fieldnames:
        raise ValueError("CSV appears to be empty or missing a header row.")
    missing = required.difference(fieldnames)
    if missing:
        raise ValueError(f"CSV missing required columns: {', '.join(sorted(missing))}. Found: {fieldnames}")


def parse_args(argv: list[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Update LogicMonitor device properties from a CSV file.")
    p.add_argument("--company", help="LogicMonitor portal subdomain (e.g. 'acme' for https://acme.logicmonitor.com). "
                                     "Env: LM_COMPANY")
    p.add_argument("--access-id", help="LogicMonitor API Access ID. Env: LM_ACCESS_ID")
    p.add_argument("--access-key", help="LogicMonitor API Access Key. Env: LM_ACCESS_KEY")
    p.add_argument("--csv", required=True, help="Path to CSV file to process.")
    p.add_argument("--dry-run", action="store_true", help="Validate and log actions without making API changes.")
    p.add_argument("--timeout", type=int, default=30, help="HTTP timeout seconds (default: 30).")
    p.add_argument("--retries", type=int, default=5, help="Max retries on transient errors (default: 5).")
    p.add_argument("--verbose", action="store_true", help="Enable debug logging.")
    return p.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )

    try:
        company = _require_env_or_arg(args.company, "LM_COMPANY", "Company")
        access_id = _require_env_or_arg(args.access_id, "LM_ACCESS_ID", "Access ID")
        access_key = _require_env_or_arg(args.access_key, "LM_ACCESS_KEY", "Access Key")
    except ValueError as e:
        LOG.error(str(e))
        return 2

    cfg = LMConfig(
        company=company,
        access_id=access_id,
        access_key=access_key,
        timeout_s=args.timeout,
        max_retries=args.retries,
    )

    csv_path = args.csv
    if not os.path.exists(csv_path):
        LOG.error("CSV file not found: %s", csv_path)
        return 2

    processed = 0
    failures = 0

    with requests.Session() as session:
        try:
            with open(csv_path, newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                _validate_csv_header(reader.fieldnames)

                for row in reader:
                    processed += 1
                    device_id = (row.get("ID") or "").strip()
                    name = (row.get("Name") or "").strip()
                    prop = (row.get("Property") or "").strip()
                    value = (row.get("Value") or "").strip()

                    if not device_id or not prop:
                        failures += 1
                        LOG.error("Row %d invalid (missing ID or Property): %s", processed, row)
                        continue

                    LOG.info("Processing: device=%s name=%s property=%s value=%s", device_id, name, prop, value)

                    try:
                        upsert_property(cfg, session, device_id, prop, value, dry_run=args.dry_run)
                    except LMAPIError as e:
                        failures += 1
                        LOG.error("Failed: device=%s property=%s. %s", device_id, prop, e)

        except ValueError as e:
            LOG.error("CSV validation error: %s", e)
            return 2
        except OSError as e:
            LOG.error("CSV read error: %s", e)
            return 2
        except LMAPIError as e:
            LOG.error("API error: %s", e)
            return 3

    LOG.info("Done. processed=%d failures=%d dry_run=%s", processed, failures, args.dry_run)
    return 0 if failures == 0 else 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

# EOF