# Definición de infraestructura de laboratorio (versión CORREGIDA). No se aprovisionan recursos reales.
# La variante insegura equivalente está aislada en lab/infra-insegura/main.tf.

terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  type        = string
  description = "Identificador de la VPC de laboratorio"
}

variable "subnet_id" {
  type        = string
  description = "Subred privada donde se asocia la interfaz de red"
}

variable "clients_cidr" {
  type        = string
  description = "Rango interno autorizado para consumir la API (no 0.0.0.0/0)"
}

resource "aws_security_group" "api" {
  name        = "api-segura-sg"
  description = "Acceso restringido a la API de laboratorio"
  vpc_id      = var.vpc_id

  ingress {
    description = "HTTPS desde la red interna de clientes autorizados"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.clients_cidr]
  }

  egress {
    description = "Salida HTTPS hacia servicios necesarios"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_interface" "api" {
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.api.id]
  description     = "Interfaz de red de la API de laboratorio"
}
