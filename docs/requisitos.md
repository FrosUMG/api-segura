# Requisitos de seguridad verificables

Cada requisito se comprueba mediante pruebas automatizadas cuyo resultado queda en
`reports/trazabilidad_requisitos.csv` (columna `requisito`).

> La columna ASVS debe completarse con el identificador exacto tomado del documento oficial de
> OWASP ASVS 5.0 (formato `v5.0.0-X.Y.Z`). No se incluyen identificadores sin verificar.

| ID | Requisito | Criterio de comprobación | Pruebas (tests/) | ASVS 5.0 |
|----|-----------|--------------------------|------------------|----------|
| SR-01 | Todo recurso protegido exige un token válido, vigente y firmado con el algoritmo esperado | Sin token, token alterado, expirado o con `alg=none` -> 401 | `test_solicitud_sin_autenticacion`, `test_token_con_firma_alterada`, `test_token_expirado`, `test_token_con_algoritmo_none_rechazado` | (completar) |
| SR-02 | Un usuario solo accede a los documentos de su propiedad (autorización por objeto) | Documento ajeno -> 404 sin contenido; el listado solo incluye recursos propios; el propietario no es asignable por el cliente | `test_acceso_legitimo_a_recurso_propio`, `test_denegacion_de_acceso_a_recurso_ajeno`, `test_listado_solo_contiene_recursos_propios`, `test_propietario_no_es_asignable_por_el_cliente` | (completar) |
| SR-03 | Las operaciones administrativas exigen rol admin y respetan reglas de negocio | Usuario común -> 403; admin no puede desactivarse a sí mismo (400); usuario desactivado pierde acceso | `test_operacion_administrativa_denegada_a_usuario_comun`, `test_administrador_no_puede_desactivarse_a_si_mismo`, `test_administrador_desactiva_usuario_y_se_bloquea_su_acceso` | (completar) |
| SR-04 | Las entradas del cliente se validan y las consultas a base de datos son parametrizadas | Entradas fuera de esquema -> 422; payload de inyección SQL no expone datos ajenos; regla Semgrep sin hallazgos en `app/` | `test_entrada_inesperada_es_rechazada`, `test_busqueda_legitima_devuelve_solo_coincidencias_propias`, `test_inyeccion_sql_en_busqueda_no_expone_datos_ajenos` | (completar) |
| SR-05 | Las credenciales y tokens se gestionan de forma segura y las respuestas no filtran información | Hash PBKDF2 (600000 iteraciones); mensaje de login uniforme; cabeceras defensivas presentes; secreto JWT obligatorio desde el entorno | `test_login_no_revela_si_el_usuario_existe`, `test_contrasenas_almacenadas_con_hash_pbkdf2`, `test_cabeceras_de_seguridad_presentes` | (completar) |
| SR-06 | Las dependencias no contienen vulnerabilidades conocidas con corrección disponible | `pip-audit` sin vulnerabilidades corregibles; la puerta bloquea cuando existen | `test_sca_*` (mecanismo) y job `sca` del pipeline | (completar) |
