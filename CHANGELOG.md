# Changelog

## [1.5.0] — 2026-08-19

### Adicionado

- **Confirmação do número de telefone pela central.** Dois métodos novos no
  `HongaAuthClient`:
  - `pedirCodigoTelefone(int $hongaUserId, string $telefone): array`
  - `confirmarCodigoTelefone(int $hongaUserId, string $pedido, string $codigo): array`

  Até aqui, quem se registava numa app escrevia um número num campo e o backend
  gravava-o: ninguém provava que o número era seu, o mesmo número podia ficar em
  várias contas, e a conta Honga Yetu — que é a identidade — continuava sem
  telefone nenhum. Quem manda o SMS passa a ser a central, que é quem tem o
  gateway e é a dona do número.

  Quando a conta **já tem** número, o `pedirCodigoTelefone` responde
  `ja_tem: true` e não sai SMS nenhum — o registo segue directo.

- **Autenticação server-to-server por `client_id` + `client_secret`.** Os dois
  métodos usam os cabeçalhos `X-Client-Id`/`X-Client-Secret` com as credenciais
  que o projecto já tem configuradas. Não há token novo para emitir no painel
  nem para colar no `.env`: um passo manual que, por dar, não dá erro nenhum —
  dá uma funcionalidade que não responde.

### Notas

- As respostas vêm tal como a central as devolve, incluindo os `estado: 'erro'`,
  mais um `http` com o código de estado. É de propósito: o backend precisa de
  distinguir "código errado" (422) de "este código já não existe" (410) para
  dizer "tenta de novo" ou "pede outro", e só ele sabe em que ecrã está quem
  vai ler a frase.
- Falha de rede devolve `{estado: 'erro', texto: …, http: 0}` em vez de lançar.

### Requer

- Central com os endpoints `POST /api/v1/sso/telefone/{codigo,confirmar}`
  (>= 2026-08-19).
