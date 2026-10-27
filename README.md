# AutoFlow

MVP SaaS para montar fluxos visuais, executar ações no servidor e acompanhar cada etapa. A aplicação tem interface em React/TypeScript e uma API Node.js. Ela usa PostgreSQL quando `DATABASE_URL` está definida e SQLite local por padrão.

## O que funciona

- Landing page pública, cadastro, login, logout e sessão por cookie seguro.
- Criação automática de um workspace por conta e isolamento das consultas pelo workspace.
- Dashboard e histórico calculados a partir das execuções persistidas.
- Editor visual com blocos manuais, HTTP, Discord, condições e registro interno.
- Validação de conexões, ciclos, gatilhos e campos obrigatórios antes de testar ou ativar.
- Execução sequencial no servidor, ramificações IF/ELSE, idempotência por chave, limites mensais e histórico por etapa.
- Requisições HTTP com timeout de 10 s, resposta limitada a 1 MB, resolução DNS validada, bloqueio de destinos privados e checagem em cada redirecionamento. A execução inteira tem limite de 60 s e 2 MB de histórico.
- Credenciais criptografadas com AES-256-GCM; a interface devolve apenas uma máscara após salvar.
- Planos e limites Free, Starter, Pro e Business representados no servidor. Não há cobrança real.

O editor executa requisições HTTP e mensagens no Discord de verdade. Ao testar ou reexecutar um fluxo, revise as ações externas configuradas.

## Requisitos

- Node.js 22.13 ou mais recente (Node 24 recomendado).
- npm.
- PostgreSQL 14+ opcional. SQLite é suficiente para desenvolvimento local.

## Rodar localmente com SQLite

```powershell
npm install
npm run dev
```

Abra `http://127.0.0.1:5173`. A API roda em `http://127.0.0.1:3001`. O banco SQLite e a chave local de criptografia são criados em `.data/`.

Para executar a versão compilada:

```powershell
npm run build
npm start
```

O servidor entrega o front-end compilado pela mesma origem da API. O padrão local é `127.0.0.1:3001`.

## PostgreSQL

O esquema inicial está em `migrations/001_init.sql` e é aplicado automaticamente ao iniciar. Para uma instância local com Docker Compose:

```powershell
docker compose up -d postgres
```

Copie `.env.example` para `.env`, configure `DATABASE_URL` e inicie o projeto:

```env
DATABASE_URL=postgres://autoflow:autoflow_local_only@127.0.0.1:5432/autoflow
```

Para uma implantação pública, substitua a senha local, configure TLS no banco e defina `PUBLIC_ORIGIN`. Configure `AUTOFLOW_CREDENTIALS_KEY` com um segredo durável compartilhado entre as instâncias; trocar essa chave torna os segredos já gravados ilegíveis. O padrão local guarda uma chave gerada em `.data/credentials.key`; preserve esse arquivo junto com o SQLite.

O PostgreSQL é suportado pela camada de persistência e pelo mesmo arquivo de migração. O projeto ainda não inclui workers, alta disponibilidade nem migrações versionadas além do esquema inicial.

## Variáveis de ambiente

| Variável | Uso |
| --- | --- |
| `DATABASE_URL` | URL PostgreSQL. Se ausente, usa SQLite. |
| `DB_PATH` | Caminho alternativo do arquivo SQLite; `:memory:` é útil em testes. |
| `DATA_DIR` | Diretório da chave local de criptografia. |
| `AUTOFLOW_CREDENTIALS_KEY` | Chave durável para criptografia AES-256-GCM. |
| `PORT` | Porta do servidor (padrão `3001`). |
| `HOST` | Endereço de escuta. Em produção, o padrão é `0.0.0.0`; localmente, `127.0.0.1`. |
| `PUBLIC_ORIGIN` | Origem pública exata permitida para operações mutáveis. |
| `TRUST_PROXY` | Habilite somente atrás de proxy confiável que substitua `X-Forwarded-For`. |
| `PGSSL` | Use `true` para conexão PostgreSQL TLS com certificado válido. |

O servidor lê `.env` nos comandos `npm run dev` e `npm start` pelo recurso `--env-file-if-exists` do Node.

## Verificação

```powershell
npm test
npm run build
```

Os testes cobrem validação de grafos, ramificação e persistência da execução, destinos SSRF privados, criptografia dos segredos, cadastro/login e isolamento entre workspaces.

## Atalhos do Windows

- `baixar.bat` verifica Node.js 22.13+, cria `.env` a partir do exemplo se necessário e instala as dependências com `npm ci`.
- `iniciar.bat` inicia `npm run dev`. Se `node_modules` ainda não existir, chama `baixar.bat` antes de iniciar.

Mantenha a janela do `iniciar.bat` aberta enquanto estiver usando a aplicação.

## Escopo ainda pendente

Esta entrega fecha a Fase 1 do MVP em versão reduzida. Gatilhos webhook, construtor de formulários, agendamentos, ação de e-mail, filas e tentativas em background, recuperação/verificação de e-mail, gestão de membros, painel administrativo, cobrança e auditoria administrativa não estão implementados. A tela de termos e privacidade informa que os documentos ainda são rascunhos. Os planos pagos são apenas uma proposta; nenhum pagamento é processado.

O gatilho disponível é manual. “Ativar” publica o fluxo e conta para o limite do plano, mas não inicia uma rotina automática enquanto os demais gatilhos não forem adicionados. Em produção, configure HTTPS no proxy, segredo estável, backups e monitoramento antes de aceitar usuários reais.
