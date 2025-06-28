#!/usr/bin/env bash
# Simple helper to switch model mode (fast | power | auto) inside .env

ENV_FILE=".env"

read -rp "Choose model mode [fast/power/auto]: " MODE

case "$MODE" in
  fast|power|auto) ;;
  *) echo "Invalid mode"; exit 1;;
esac

# Create .env if missing
[[ -f "$ENV_FILE" ]] || touch "$ENV_FILE"

# Remove existing line
grep -v '^OPENROUTER_MODEL_MODE=' "$ENV_FILE" > "$ENV_FILE.tmp" && mv "$ENV_FILE.tmp" "$ENV_FILE"

# Append new setting
printf '\nOPENROUTER_MODEL_MODE=%s\n' "$MODE" >> "$ENV_FILE"

echo "Model mode set to $MODE in $ENV_FILE" 