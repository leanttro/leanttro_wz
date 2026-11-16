#!/bin/sh
set -e
# cria/atualiza as tabelas (idempotente) e sincroniza o admin com o .env; depois sobe o gunicorn
python app.py init-db
exec gunicorn -c gunicorn.conf.py app:app
