# Troubleshooting Log

## 1. **Issue Title**
Open WebUI could not connect to Ollama on Linux due to Docker network isolation

## 2. **Date:**  
2025-06-28

## 3. **Category:**  
DevOps / GPT/AI

## 4. **Symptoms:**  
Open WebUI showed repeated connection errors trying to reach `host.docker.internal:11434`. Logs included:
ERROR - Cannot connect to host host.docker.internal:11434 ssl:default [Name or service not known]

markdown

Even direct `curl` commands inside the container to `host.docker.internal` and `172.17.0.1` failed.

## 5. **Diagnosis Process:**

- Confirmed Ollama was running with:
  ```bash
  curl http://localhost:11434
Attempted to access Ollama via Docker host IP:

```bash
docker exec -it open-webui curl http://host.docker.internal:11434
docker exec -it open-webui curl http://172.17.0.1:11434
Both failed with curl: (7) connection errors.

Determined containers were isolated due to default bridge networking.

Created a user-defined Docker network:

```bash
docker network create ollama-net
Re-deployed Ollama on this network:

```bash
docker run -d \
  --name ollama \
  --network ollama-net \
  -v ~/ollama:/root/.ollama \
  -p 11434:11434 \
  ollama/ollama
Re-deployed Open WebUI on the same network with direct container reference:

```bash
docker run -d \
  --name open-webui \
  --network ollama-net \
  -p 3000:3000 \
  -e OLLAMA_BASE_URL=http://ollama:11434 \
  ghcr.io/open-webui/open-webui:main
  
Confirmed internal connectivity:

```bash
docker exec -it open-webui curl http://ollama:11434



6. Root Cause:
On Linux, host.docker.internal does not resolve by default. Docker containers on the default bridge network were isolated from the host and each other, preventing Open WebUI from reaching the Ollama API.

7. Fix Implemented:
Created a shared Docker network (ollama-net) and re-ran both containers on it. Reconfigured OLLAMA_BASE_URL to use http://ollama:11434 (the container name), allowing direct container-to-container communication.

8. Lessons Learned:
host.docker.internal is not available on Linux unless explicitly mapped with --add-host or using Docker's host-gateway (if supported).

Use a shared Docker network to enable container-to-container communication.

Referencing containers by name is a clean and scalable approach in Dockerized environments.

9. Next Steps (Optional):
Add NGINX reverse proxy for multi-user access and authentication.

Create a docker-compose.yml for simpler orchestration and automatic restarts.

Secure with HTTPS and optionally implement user access controls.

