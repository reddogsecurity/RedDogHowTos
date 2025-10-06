# SpiderFoot Docker Image Fails to Build and Access

**Date:** 2025-06-28  
**Category:** OSINT / DevOps  

---

## 1. **Issue Title**  
Failed to pull or build SpiderFoot Docker image; blocking OSINT tool deployment.

---

## 2. **Symptoms**

- Attempting to deploy SpiderFoot via Docker Compose resulted in:
ERROR: pull access denied for spiderfoot/spiderfoot, repository does not exist or may require 'docker login'



- Switching to `smicallef/spiderfoot` yielded the same error:
pull access denied for smicallef/spiderfoot, repository does not exist



- Building from source failed due to:
COPY $REQUIREMENTS requirements.txt ./
→ "/requirements.txt": not found



- Later, pip install failed during image build:
ERROR: failed to solve: pip install -r requirements.txt


---

## 3. **Diagnosis Process**

- Attempted to pull known public Docker Hub images:
```bash
docker pull spiderfoot/spiderfoot
docker pull smicallef/spiderfoot
Confirmed image unavailability on Docker Hub.

Cloned the official SpiderFoot GitHub repo:

```bash
git clone https://github.com/smicallef/spiderfoot.git
cd spiderfoot
Verified presence of sf.py and requirements.txt.

Created a custom Dockerfile to build image locally.

Attempted to install Python dependencies inside Docker container.

4. Root Cause
No official public image currently exists on Docker Hub under either spiderfoot/spiderfoot or smicallef/spiderfoot.

The default Dockerfile in the repo references undefined variables ($REQUIREMENTS) and has legacy ENV syntax.

pip install errors were caused by dependency issues or Docker cache inconsistencies.

5. Fix Implemented
Created a clean, custom Dockerfile that:

Installs system and Python dependencies

Copies project files to /app

Installs from requirements.txt

Runs sf.py on port 5001

Dockerfile:

FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    git nmap curl build-essential libssl-dev \
    libffi-dev python3-dev && apt-get clean && rm -rf /var/lib/apt/lists/*

COPY . .

RUN pip install --upgrade pip
RUN pip install -r requirements.txt

EXPOSE 5001

CMD ["python3", "sf.py", "-l", "0.0.0.0:5001"]
Added the service to docker-compose.yml:


services:
  spiderfoot:
    build: .
    container_name: spiderfoot
    restart: unless-stopped
    ports:
      - "5001:5001"
    volumes:
      - spiderfoot-data:/root/.spiderfoot
volumes:
  spiderfoot-data:
Verified successful build and access via browser at http://localhost:5001.

6. Lessons Learned
Always validate public Docker image availability before referencing in Compose files.

Legacy Dockerfiles in older OSS projects may be outdated or misconfigured.

Building locally provides more control and stability when official images are unavailable.

Use a well-scoped Dockerfile with known-good base images and explicit commands.

7. Next Steps (Optional)
Monitor container health and add NGINX reverse proxy + basic auth.

Add SSL with Certbot.

Create a scheduled scan system + PDF exporter using FastAPI.

Evaluate integration with PostgreSQL for better data access.


