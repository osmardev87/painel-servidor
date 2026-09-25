#!/usr/bin/env bash
set -euo pipefail

username="${1:-painelterminal}"
if [[ ! "$username" =~ ^[a-z_][a-z0-9_-]*[$]?$ ]]; then
  echo "Nome de usuario Linux invalido." >&2
  exit 1
fi
if [[ "$username" == "root" ]]; then
  echo "O terminal nao pode usar a conta root." >&2
  exit 1
fi
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Execute como root." >&2
  exit 1
fi

if ! id "$username" >/dev/null 2>&1; then
  useradd --create-home --user-group --shell /bin/bash "$username"
fi

if [[ "$(id -u "$username")" -eq 0 ]]; then
  echo "A conta nao pode ter UID 0." >&2
  exit 1
fi
primary_group="$(id -gn "$username")"
if [[ "$primary_group" != "$username" ]]; then
  echo "A conta ja existe com o grupo principal '$primary_group'. Nao alterei essa conta." >&2
  exit 1
fi
passwd --lock "$username" >/dev/null

echo "Conta pronta: $username"
echo "Sem senha de login, sem sudo e sem grupo Docker."
echo "Configure TERMINAL_USER=$username no .env e reinicie o PM2."
