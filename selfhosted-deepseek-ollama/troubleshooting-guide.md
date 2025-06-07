
Use a Shared Docker Network

Step 1: Create a Docker Network

docker network create ollama-net


Step 2: Start Ollama on That Network

docker run -d \
  --name ollama \
  --network ollama-net \
  -v ~/ollama:/root/.ollama \
  -p 11434:11434 \
  ollama/ollama


Step 3: Start Open WebUI on Same Network

docker run -d \
  --name open-webui \
  --network ollama-net \
  -p 3000:3000 \
  -e OLLAMA_BASE_URL=http://ollama:11434 \
  ghcr.io/open-webui/open-webui:main


This ensures that the open-webui container can resolve ollama as a hostname.

🔍 Confirm It Works
You can verify the connection from within the Open WebUI container:

docker exec -it open-webui curl http://ollama:11434

Expected Output:


{"models":[...]}
🧪 Additional Debug Tips

Check Docker Network:

docker network inspect ollama-net

Restart Both Containers After Changes:


docker-compose down
docker-compose up -d

If using Docker Compose, ensure both services share the same network and OLLAMA_BASE_URL is configured correctly.

🛡 NGINX Notes (If Enabled)
If you're using NGINX as a reverse proxy:

Ensure it's on the same Docker network (ollama-net)

Confirm proxy settings in nginx/default.conf

Check basic auth isn't blocking the WebUI unexpectedly

📓 Related Docs

Ollama GitHub (https://github.com/jmorganca/ollama)

Open WebUI GitHub (https://github.com/open-webui/open-webui)

Docker Networking Guide (https://docs.docker.com/network/bridge/)

🤝 Contributing
If you encounter other issues not listed here, please open an issue or submit a pull request to improve this guide.


# 🛠 Troubleshooting Guide: Ollama + Open WebUI Stack

This guide documents common issues and proven solutions encountered while running [Ollama](https://ollama.com) with [Open WebUI](https://github.com/open-webui/open-webui) in a Docker-based self-hosted environment on Linux.

---

## ❌ Issue: Open WebUI Can't Connect to Ollama

**Symptom:**
```bash
Connection error: Cannot connect to host host.docker.internal:11434


## 📊 Docker Network Diagram (Architecture)

```mermaid
flowchart LR
    subgraph Docker_Network ["Docker Network: ollama-net"]
        OLLAMA[🧠 Ollama\nPort: 11434]
        OPENWEBUI[💬 Open WebUI\nPort: 3000]
        NGINX[🌐 NGINX Proxy\nPort: 80]
        OLLAMA <--> OPENWEBUI
        OPENWEBUI <--> NGINX
    end

    CLIENT[👤 Browser] --> NGINX



