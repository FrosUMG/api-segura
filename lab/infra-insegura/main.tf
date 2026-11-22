# *** CONFIGURACIÓN INSEGURA DE LABORATORIO: NO APLICAR NI DESPLEGAR ***
# Se usa únicamente para demostrar la detección con Checkov. No se aprovisionan recursos reales.

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

variable "vpc_id" {
  type = string
}

variable "subnet_id" {
  type = string
}

resource "aws_security_group" "api" {
  name   = "api-segura-sg"
  vpc_id = var.vpc_id

  # Defecto 1: SSH abierto a todo Internet
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Defecto 2: HTTP (puerto 80) abierto a todo Internet, sin descripción
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Defecto 3: salida irrestricta a cualquier destino y protocolo
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_network_interface" "api" {
  subnet_id       = var.subnet_id
  security_groups = [aws_security_group.api.id]
}
