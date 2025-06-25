# 🔐 Secure React App - Azure AD + Key Vault Integration

A modular web application built using React (frontend), Node.js (backend), and Azure services (AD, Key Vault), deployed via Docker on a Linux server.

---

## 🧩 Modules Overview

| Module        | Description                                 | Stack                      |
|---------------|---------------------------------------------|----------------------------|
| Frontend      | React app with Azure AD auth via MSAL       | React, MSAL.js, Axios      |
| Backend       | Express server exposing secure API          | Node.js, Azure SDK         |
| Vault Service | Retrieves secrets from Azure Key Vault      | Azure Key Vault, App Reg   |
| DevOps        | Docker + Azure DevOps Pipelines             | NGINX, Certbot, Docker     |

---

## 📐 Architecture Diagram

📁 See `/docs/architecture.png` (or refer to included PNG file)

---

## 🗂 Project Structure

