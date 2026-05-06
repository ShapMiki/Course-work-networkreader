#!/bin/bash
cd "$(dirname "$0")"
source venv/bin/activate
echo "Введите пароль для запуска сниффера (права root)..."
sudo venv/bin/python3 server.py
