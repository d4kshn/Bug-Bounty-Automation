from __future__ import annotations

import fnmatch
import ipaddress
import socket
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from bbpipeline.manifest import ProgramManifest, ScopeRule


@dataclass(frozen=True)
class ScopeDecision:
    allowed: bool
    reason: str
    target: str
    resolved_ips: tuple[str, ...] = field(default_factory=tuple)


def normalize_hostname(hostname: str) -> str:
    return hostname.strip().rstrip(".").lower().encode("idna").decode("ascii")


def _domain_matches(pattern: str, hostname: str) -> bool:
    pattern = normalize_hostname(pattern)
    hostname = normalize_hostname(hostname)
    if pattern.startswith("*."):
        suffix = pattern[2:]
        return hostname.endswith("." + suffix) and hostname != suffix
    return hostname == pattern


def _url_matches(pattern: str, target: str) -> bool:
    expected = urlsplit(pattern)
    actual = urlsplit(target)
    if expected.scheme and expected.scheme.lower() != actual.scheme.lower():
        return False
    if not expected.hostname or not actual.hostname:
        return False
    if not _domain_matches(expected.hostname, actual.hostname):
        return False
    expected_port = expected.port or (443 if expected.scheme == "https" else 80)
    actual_port = actual.port or (443 if actual.scheme == "https" else 80)
    if expected_port != actual_port:
        return False
    prefix = expected.path or "/"
    path = actual.path or "/"
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def _repo_matches(pattern: str, repository: str) -> bool:
    return fnmatch.fnmatchcase(repository.lower(), pattern.lower())


def _cloud_matches(pattern: str, resource: str) -> bool:
    return fnmatch.fnmatchcase(resource.lower(), pattern.lower())


def _cidr_matches(cidr: str, address: str) -> bool:
    try:
        allowed = ipaddress.ip_network(cidr, strict=False)
        if "/" in address:
            candidate = ipaddress.ip_network(address, strict=False)
            return candidate.subnet_of(allowed)
        return ipaddress.ip_address(address) in allowed
    except ValueError:
        return False


def rule_matches(rule: ScopeRule, target: str) -> bool:
    if rule.type == "repository":
        return _repo_matches(rule.value, target)
    if rule.type == "cloud":
        return _cloud_matches(rule.value, target)
    if rule.type == "cidr":
        return _cidr_matches(rule.value, target)

    parsed = urlsplit(target if "://" in target else f"//{target}")
    hostname = parsed.hostname
    if not hostname:
        return False
    if rule.type == "domain":
        return _domain_matches(rule.value, hostname)
    if rule.type == "url":
        return "://" in target and _url_matches(rule.value, target)
    return False


def resolve_host(hostname: str) -> tuple[str, ...]:
    addresses = {
        item[4][0]
        for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        if item and item[4]
    }
    return tuple(sorted(addresses))


def _explicit_ip_in_scope(manifest: ProgramManifest, address: str) -> bool:
    return any(
        rule.type == "cidr" and _cidr_matches(rule.value, address)
        for rule in manifest.scope.include
    )


def authorize_target(
    manifest: ProgramManifest,
    target: str,
    *,
    method: str = "GET",
    resolve_dns: bool | None = None,
    resolver=resolve_host,
) -> ScopeDecision:
    method = method.upper()
    if method not in manifest.network.allowed_methods:
        return ScopeDecision(False, f"HTTP method {method} is not allowed", target)

    for rule in manifest.scope.exclude:
        if rule_matches(rule, target):
            return ScopeDecision(False, f"target matches excluded {rule.type} rule", target)

    if not any(rule_matches(rule, target) for rule in manifest.scope.include):
        return ScopeDecision(False, "target does not match an in-scope rule", target)

    try:
        target_network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        target_network = None
    if (
        target_network is not None
        and target_network.num_addresses > manifest.network.max_cidr_addresses
    ):
        return ScopeDecision(
            False,
            f"CIDR expands beyond {manifest.network.max_cidr_addresses} approved addresses",
            target,
        )

    parsed = urlsplit(target if "://" in target else f"//{target}")
    hostname = parsed.hostname
    if parsed.scheme:
        if manifest.network.require_https and parsed.scheme.lower() != "https":
            return ScopeDecision(False, "program requires HTTPS", target)
        port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
        if port not in manifest.network.allowed_ports:
            return ScopeDecision(False, f"port {port} is not allowed", target)
        path = parsed.path or "/"
        if any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in manifest.network.denied_paths
        ):
            return ScopeDecision(False, "path matches a denied pattern", target)
        if not any(
            fnmatch.fnmatchcase(path, pattern)
            for pattern in manifest.network.allowed_paths
        ):
            return ScopeDecision(False, "path does not match an allowed pattern", target)

    should_resolve = manifest.network.resolve_before_scan if resolve_dns is None else resolve_dns
    if not should_resolve or not hostname:
        return ScopeDecision(True, "target matches approved scope", target)

    try:
        ipaddress.ip_address(hostname)
        addresses = (hostname,)
    except ValueError:
        try:
            addresses = tuple(resolver(hostname))
        except (OSError, socket.gaierror) as exc:
            return ScopeDecision(False, f"DNS resolution failed: {exc}", target)
    if not addresses:
        return ScopeDecision(False, "target resolved to no addresses", target)

    for address in addresses:
        if any(
            rule.type == "cidr" and _cidr_matches(rule.value, address)
            for rule in manifest.scope.exclude
        ):
            return ScopeDecision(
                False, f"resolved address {address} is excluded", target, addresses
            )
        ip = ipaddress.ip_address(address)
        if not ip.is_global and not manifest.network.allow_private_targets:
            if not _explicit_ip_in_scope(manifest, address):
                return ScopeDecision(
                    False,
                    f"resolved address {address} is not globally routable or explicitly allowed",
                    target,
                    addresses,
                )

    return ScopeDecision(True, "target and resolved addresses match policy", target, addresses)


def authorize_many(
    manifest: ProgramManifest,
    targets: list[str],
    *,
    method: str = "GET",
    resolver=resolve_host,
) -> list[ScopeDecision]:
    return [
        authorize_target(manifest, target, method=method, resolver=resolver) for target in targets
    ]
