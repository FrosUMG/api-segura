package apisegura.deploy

import rego.v1

# Política de configuración de despliegue. Cada regla "deny" describe una configuración
# insegura concreta; si el conjunto "deny" no está vacío, el proceso automatizado debe fallar
# (ver el comando `opa eval --fail-defined` en el workflow y en el README).

user := object.get(input, ["container", "user"], "")

# 1. El contenedor no debe ejecutarse como root.
deny contains msg if {
	user in {"", "root", "0"}
	msg := "BLOQUEO: el contenedor debe ejecutarse con un usuario sin privilegios (no root)"
}

# 2. El modo de depuración no debe estar habilitado.
deny contains msg if {
	object.get(input, ["app", "debug"], false) == true
	msg := "BLOQUEO: el modo debug no debe estar habilitado"
}

# 3. El secreto de firma JWT debe provenir del entorno.
deny contains msg if {
	object.get(input, ["app", "jwt_secret_source"], "") != "env"
	msg := "BLOQUEO: el secreto JWT debe provenir de variables de entorno (no del código ni de archivos versionados)"
}

# 4. Vigencia máxima de tokens: 60 minutos.
deny contains msg if {
	object.get(input, ["app", "jwt_ttl_minutes"], 0) > 60
	msg := "BLOQUEO: la vigencia de los tokens JWT no debe superar 60 minutos"
}

# 5. Orígenes permitidos: no se admite el comodín.
deny contains msg if {
	"*" in object.get(input, ["network", "allowed_origins"], [])
	msg := "BLOQUEO: allowed_origins no debe contener el comodín '*'"
}
