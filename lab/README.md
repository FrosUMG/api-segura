# lab/: material deliberadamente vulnerable (AISLADO)

**No desplegar. No exponer a Internet. No incluir en el pipeline principal.**

| Archivo | Propósito |
|---|---|
| `vulnerable.patch` | Reintroduce dos defectos en `app/routes_documents.py`: BOLA/IDOR en `GET /documents/{id}` e inyección SQL en `GET /documents/search`. Se aplica con `git apply` en la rama `lab/vulnerable`; `git apply -R` aplica la corrección. |
| `infra-insegura/main.tf` | Configuración Terraform insegura (SSH y HTTP abiertos a todo Internet, egreso irrestricto). Se evalúa con Checkov y se corrige en `infra/main.tf`. No se aprovisiona nada. |
| `deployment-insegura.json` | Entrada que la política OPA debe denegar. La entrada permitida es `deploy/deployment.json`. |
