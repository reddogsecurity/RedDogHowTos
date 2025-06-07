# Self-Hosted Ollama + Open WebUI Setup

> Local LLM playground using Ollama, Open WebUI, and DeepSeek. Docker-based setup with optional NGINX for multi-user access.

## 🔧 What's Included
- Ollama container with DeepSeek models
- Open WebUI interface
- Docker network bridging
- Optional NGINX reverse proxy
- Automatic restart on reboot

## 🧱 Requirements
- Linux host (tested on Ubuntu)
- Docker & docker-compose
- 8GB+ RAM recommended

## 🚀 Quick Start

```bash
git clone https://github.com/your-org/selfhosted-deepseek-ollama
cd selfhosted-deepseek-ollama
docker-compose up -d