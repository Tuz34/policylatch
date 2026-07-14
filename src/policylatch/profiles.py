from __future__ import annotations

from copy import deepcopy
from typing import Any

BUILTIN_PROFILES: dict[str, dict[str, Any]] = {
    "minimal": {
        "version": 1,
        "default_decision": "allow",
        "rules": {
            "shell": {
                "deny_patterns": ["rm -rf", "Remove-Item -Recurse", "curl * | sh"],
            },
            "files": {
                "deny_paths": [".env", "**/.env", "**/secrets/**", "**/id_rsa"],
            },
            "network": {
                "deny_domains": ["*.pastebin.com", "*.webhook.site"],
            },
            "mcp_tools": {
                "deny_if_description_contains": [
                    "ignore previous instructions",
                    "exfiltrate",
                ],
            },
        },
    },
    "balanced": {
        "version": 1,
        "default_decision": "allow",
        "rules": {
            "shell": {
                "deny_patterns": [
                    "rm -rf",
                    "Remove-Item -Recurse",
                    "curl * | sh",
                    "Invoke-WebRequest * | iex",
                ],
                "warn_patterns": ["git push", "npm publish", "pip install"],
            },
            "files": {
                "deny_paths": [
                    ".env",
                    "**/.env",
                    "**/secrets/**",
                    "**/credentials/**",
                    "**/id_rsa",
                ],
                "warn_paths": ["**/config/**", "**/*.pem"],
            },
            "network": {
                "allow_domains": ["github.com", "modelcontextprotocol.io"],
                "deny_domains": ["*.pastebin.com", "*.webhook.site"],
            },
            "mcp_tools": {
                "deny_if_description_contains": [
                    "ignore previous instructions",
                    "send file contents",
                    "exfiltrate",
                ],
                "warn_if_name_contains": ["shell", "exec", "browser", "database"],
                "warn_if_schema_contains": ["command", "path", "url"],
            },
        },
    },
    "strict": {
        "version": 1,
        "default_decision": "warn",
        "rules": {
            "shell": {
                "deny_patterns": [
                    "rm -rf",
                    "Remove-Item -Recurse",
                    "curl * | sh",
                    "Invoke-WebRequest * | iex",
                    "git push --force",
                ],
                "warn_patterns": ["git push", "npm publish", "pip install"],
            },
            "files": {
                "deny_paths": [
                    ".env",
                    "**/.env",
                    "**/secrets/**",
                    "**/credentials/**",
                    "**/*.pem",
                    "**/id_rsa",
                ],
                "warn_paths": ["**/config/**"],
            },
            "network": {
                "allow_domains": ["github.com"],
                "deny_domains": ["*.pastebin.com", "*.webhook.site"],
            },
            "mcp_tools": {
                "deny_if_description_contains": [
                    "ignore previous instructions",
                    "send file contents",
                    "exfiltrate",
                    "no approval needed",
                ],
                "warn_if_name_contains": ["shell", "exec", "browser", "database"],
                "warn_if_schema_contains": ["command", "path", "url"],
            },
        },
    },
    "ci": {
        "version": 1,
        "default_decision": "allow",
        "rules": {
            "shell": {
                "deny_patterns": ["rm -rf", "Remove-Item -Recurse", "git push --force"],
                "warn_patterns": ["npm publish"],
            },
            "files": {
                "deny_paths": [".env", "**/.env", "**/secrets/**", "**/id_rsa"],
                "warn_paths": [],
            },
            "network": {
                "allow_domains": ["github.com"],
                "deny_domains": ["*.webhook.site"],
            },
            "mcp_tools": {
                "deny_if_description_contains": [
                    "ignore previous instructions",
                    "exfiltrate",
                ],
                "warn_if_name_contains": ["shell", "exec"],
                "warn_if_schema_contains": ["command", "path", "url"],
            },
        },
    },
}


def profile_names() -> tuple[str, ...]:
    return tuple(sorted(BUILTIN_PROFILES))


def builtin_profile(name: str) -> dict[str, Any]:
    try:
        return deepcopy(BUILTIN_PROFILES[name])
    except KeyError as exc:
        available = ", ".join(profile_names())
        raise ValueError(
            f"Unknown policy profile '{name}'. Available profiles: {available}."
        ) from exc
