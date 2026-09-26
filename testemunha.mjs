// TESTEMUNHA W2 (GitHub Actions). Baixa a cadeia PÚBLICA de batimentos, confere tudo sozinha e assina com a PRÓPRIA chave (segredo do repositório).
// A publicação é o `git push` do workflow: a assinatura só existe para o mundo se o push for aceito; estado (época, cabeça) e cosign vão no MESMO commit
// (atômico). Se o push falhar por corrida, nada foi publicado e a próxima execução refaz. Nunca assina duas cabeças para a mesma época (ver nucleo.mjs).
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { assinarCosign, decidir } from './nucleo.mjs';

const { API, CHAVE_GRUPO, TESTEMUNHA_CHAVE, HC_PING_URL } = process.env;
const ID = process.env.ID ?? 'W2', CANAL = process.env.CANAL ?? 'principal';
if (!API || !CHAVE_GRUPO || !TESTEMUNHA_CHAVE) { console.error('faltam API, CHAVE_GRUPO ou TESTEMUNHA_CHAVE'); process.exit(2); }
const estado = existsSync('estado.json') ? JSON.parse(readFileSync('estado.json', 'utf8')) : null;
const r = await fetch(`${API}/shield/batimentos?canal=${CANAL}&limite=120`, { headers: { Accept: 'application/json' } });
if (!r.ok) { console.log(`API ${r.status}: nada a fazer`); process.exit(0); }
const lista = (await r.json())?.data?.batimentos ?? [];
const d = await decidir({ estado, lista, chaveGrupo: CHAVE_GRUPO, canal: CANAL, testemunha: ID });
console.log(JSON.stringify({ testemunha: ID, acao: d.acao, motivo: d.motivo, epoca: d.cosign?.epoca }));
if (d.acao === 'recusar') {
  if (HC_PING_URL && ['equivocacao', 'recuo', 'cadeia_com_problema'].includes(d.alerta)) await fetch(`${HC_PING_URL.replace(/\/$/, '')}/fail`, { method: 'POST', body: `Testemunha ${ID} recusou: ${d.motivo}`.slice(0, 900) }).catch(() => undefined);
  process.exit(0);
}
const assinatura = await assinarCosign(d.cosign, TESTEMUNHA_CHAVE);
if (d.acao === 'assinar') writeFileSync('estado.json', JSON.stringify(d.novoEstado) + '\n');
writeFileSync('cosign.json', JSON.stringify({ ok: true, cosign: d.cosign, assinatura, em: new Date().toISOString() }) + '\n');
