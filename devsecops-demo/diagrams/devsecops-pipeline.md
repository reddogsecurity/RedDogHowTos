"markdown.styles": [
    "https://use.fontawesome.com/releases/v5.7.1/css/all.css"
]
```mermaid
graph TD;
    A[Developer Workstation] --> B[GitHub Repo];
    B --> C[Pre-commit Hooks<br/>🔍 detect-secrets, bandit, black];
    C --> D[CI/CD Pipeline<br/>GitHub Actions / Azure Pipelines];
    D --> E[Static Analysis<br/>🧪 SAST, Linting, Type Checks];
    D --> F[Dependency Scanning<br/>📦 pip-audit, npm audit];
    D --> G[Secrets Scanning<br/>🔐 GitHub Advanced Security];
    D --> H[Docker Image Build<br/>🐳 Hardened, Non-root User];
    H --> I[Staging Server<br/>🧪 UAT, Manual Approval];
    I --> J[Production Server];
    J --> K[Monitoring & Alerts<br/>📈 Netdata, Uptime Kuma]