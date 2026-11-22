package apisegura.deploy_test

import data.apisegura.deploy
import rego.v1

valid := {
	"container": {"user": "appuser"},
	"app": {"debug": false, "jwt_secret_source": "env", "jwt_ttl_minutes": 15},
	"network": {"allowed_origins": []},
}

# Entrada PERMITIDA: ninguna regla deny se activa.
test_configuracion_segura_es_permitida if {
	denied := deploy.deny with input as valid
	count(denied) == 0
}

# Entradas DENEGADAS: cada configuración insegura activa exactamente una regla.
test_usuario_root_es_denegado if {
	denied := deploy.deny with input as object.union(valid, {"container": {"user": "root"}})
	count(denied) == 1
}

test_usuario_ausente_es_denegado if {
	denied := deploy.deny with input as object.remove(valid, ["container"])
	count(denied) == 1
}

test_debug_habilitado_es_denegado if {
	denied := deploy.deny with input as object.union(valid, {"app": {"debug": true, "jwt_secret_source": "env", "jwt_ttl_minutes": 15}})
	count(denied) == 1
}

test_secreto_embebido_es_denegado if {
	denied := deploy.deny with input as object.union(valid, {"app": {"debug": false, "jwt_secret_source": "hardcoded", "jwt_ttl_minutes": 15}})
	count(denied) == 1
}

test_ttl_excesivo_es_denegado if {
	denied := deploy.deny with input as object.union(valid, {"app": {"debug": false, "jwt_secret_source": "env", "jwt_ttl_minutes": 1440}})
	count(denied) == 1
}

test_origen_comodin_es_denegado if {
	denied := deploy.deny with input as object.union(valid, {"network": {"allowed_origins": ["*"]}})
	count(denied) == 1
}
