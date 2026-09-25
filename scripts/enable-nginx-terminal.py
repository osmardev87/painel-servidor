#!/usr/bin/env python3
"""Enable the panel's WebSocket route in its existing HTTPS Nginx vhost."""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from datetime import datetime
from pathlib import Path


def panel_domain() -> str:
    if len(sys.argv) > 1:
        return sys.argv[1].strip()
    if os.environ.get("ORIGIN"):
        return os.environ["ORIGIN"].strip().split("://", 1)[-1].split("/", 1)[0]

    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            match = re.match(r"\s*ORIGIN\s*=\s*['\"]?([^\s'\"]+)", line)
            if match:
                return match.group(1).split("://", 1)[-1].split("/", 1)[0]
    raise SystemExit("Nao encontrei ORIGIN. Rode: python3 scripts/enable-nginx-terminal.py seu.dominio.com")


def closing_brace(text: str, opening: int) -> int | None:
    depth = 0
    quote = None
    escaped = False
    comment = False
    for index in range(opening, len(text)):
        char = text[index]
        if comment:
            if char == "\n":
                comment = False
            continue
        if quote:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char == "#":
            comment = True
        elif char in ("'", '"'):
            quote = char
        elif char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def candidate_configs() -> list[Path]:
    nginx = Path("/etc/nginx")
    candidates = [nginx / "nginx.conf"]
    for directory in (nginx / "sites-enabled", nginx / "conf.d"):
        if directory.exists():
            candidates.extend(path for path in directory.rglob("*") if path.is_file())
    unique = {}
    for path in candidates:
        try:
            resolved = path.resolve(strict=True)
            unique[str(resolved)] = resolved
        except OSError:
            continue
    return list(unique.values())


def matching_server(text: str, domain: str) -> tuple[int, int] | None:
    starts = re.finditer(r"(?m)^[ \t]*server\s*\{", text)
    for match in starts:
        opening = text.find("{", match.start(), match.end())
        closing = closing_brace(text, opening)
        if closing is None:
            continue
        block = text[opening:closing + 1]
        has_domain = re.search(r"\bserver_name\s+[^;]*\b" + re.escape(domain) + r"\b[^;]*;", block)
        is_https = re.search(r"\blisten\s+(?:\[::\]:)?443\b[^;]*;", block)
        if has_domain and is_https:
            return opening, closing
    return None


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("Rode este script como root: python3 scripts/enable-nginx-terminal.py")

    domain = panel_domain()
    matches: list[tuple[Path, int, int, str]] = []
    for path in candidate_configs():
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError):
            continue
        server = matching_server(text, domain)
        if server:
            matches.append((path, server[0], server[1], text))

    if len(matches) != 1:
        if not matches:
            raise SystemExit(f"Nao achei um vhost HTTPS unico para {domain} em /etc/nginx.")
        raise SystemExit(f"Achei {len(matches)} vhosts HTTPS para {domain}; ajuste manualmente para evitar alterar o arquivo errado.")

    path, opening, closing, text = matches[0]
    block = text[opening:closing + 1]
    if re.search(r"\blocation\s*=\s*/terminal\b", block):
        print(f"A rota /terminal ja existe em {path}; nenhuma alteracao feita.")
        return

    location = '''

    # Web terminal: forward the authenticated WebSocket to the panel.
    location = /terminal {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 8h;
        proxy_send_timeout 8h;
        proxy_buffering off;
    }
'''
    updated = text[:closing] + location + text[closing:]
    backup = path.with_name(path.name + ".backup-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    shutil.copy2(path, backup)
    path.write_text(updated, encoding="utf-8")

    check = subprocess.run(["nginx", "-t"], check=False)
    if check.returncode:
        shutil.copy2(backup, path)
        raise SystemExit(f"nginx -t falhou; restaurei o arquivo original. Backup: {backup}")

    reload_result = subprocess.run(["systemctl", "reload", "nginx"], check=False)
    if reload_result.returncode:
        raise SystemExit(f"Configuracao valida, mas o reload falhou. Arquivo: {path}; backup: {backup}")

    print(f"WebSocket /terminal habilitado em {path}.")
    print(f"Backup criado em {backup}.")


if __name__ == "__main__":
    main()
