# WHAZIDEIA SaaS

Flask + SQLite. Cadastro grátis com código por e-mail, login, painel `/admin` (bloquear, excluir, criar conta; nunca mostra o conteúdo das pessoas) e API `PUT /api/data/<chave>` que substitui o localStorage do app.

## Deploy no Dokploy
1. Suba este repositório no GitHub.
2. **Volume:** monte um volume persistente em `/data` (é onde fica o `db.sqlite`).
3. Crie uma **Application** apontando para o repo (Build Type: **Dockerfile**, porta **8000**).
4. Preencha as variáveis de `.env.example` na aba Environment.
5. Deploy e aponte o domínio. O HTTPS fica por conta do Dokploy.

Páginas: `/cadastro`, `/login`, `/app`, `/conta`, `/admin`.

## Teste local
`DEBUG=1 python app.py run` (SQLite em ./data, o código de e-mail aparece no log).
