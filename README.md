# Plataforma abierta de inteligencia de ciberamenazas

Despliegue del sistema de inteligencia de ciberamenazas desarrollado como Trabajo de
Fin de Grado (Grado en Ingeniería Telemática, Universitat de les Illes Balears).
Integra OpenCTI como núcleo de inteligencia, TheHive como gestor de incidentes y n8n
como orquestador de automatización, sobre una infraestructura Docker Compose, junto
con un conector personalizado en Python para vincular casos con técnicas de la matriz
MITRE ATT&CK.

La detección con Falco se ejecuta en una máquina virtual independiente y no forma
parte de este despliegue.

## Estructura

- `/opencti` — Stack principal: OpenCTI + Elasticsearch + Redis + RabbitMQ + Minio + conectores oficiales
- `/thehive` — Stack de TheHive: Cassandra + Elasticsearch + TheHive + nginx
- `/n8n` — Orquestador n8n
- `/mitre-connector` — Conector personalizado Falco → MITRE ATT&CK

## Despliegue

```bash
docker network create soc-network

cd opencti          && cp .env.example .env && docker compose up -d
cd ../thehive        && cp .env.example .env && docker compose up -d
cd ../n8n            && cp .env.example .env && docker compose up -d
cd ../mitre-connector && cp .env.example .env && docker compose up -d
```

Rellena cada `.env` con tus propias contraseñas y claves de API antes de arrancar.
