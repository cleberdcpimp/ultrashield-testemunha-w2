// VIGIA DE FORA (Cloudflare Worker, cron a cada 5 min): confere, de OUTRO fornecedor e sem depender do PC do operador, a cadeia de batimentos
// assinados publicada em /shield/batimentos. Mesma conferência da página de status (Ed25519 do grupo fixado + elos da cadeia + frescor).
// Se algo estiver errado, avisa o Healthchecks (/fail) -> e-mail para o operador. Se estiver tudo certo, não faz nada (quem confirma "vivo" são as sentinelas).
// Só LEITURA da API pública; não tem rota (workers_dev=false); não guarda segredo além da URL do Healthchecks.
export const DOMINIO = 'ultrashield-batimento-v1\n';
const ZEROS = '0'.repeat(64);

const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hexBytes = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const paraHex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');
const sha256 = async (t) => paraHex(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(t)));

/** Confere a cadeia e devolve { problemas, heads } (heads: Map época -> hash do batimento). `lista` = como vem da API; `agoraMs` injetável p/ teste. */
export async function analisar(lista, chaveSpkiB64, agoraMs = Date.now(), maxIdadeMs = 15 * 60_000) {
  const problemas = [];
  const heads = new Map();
  if (!Array.isArray(lista) || lista.length === 0) return { problemas: ['a API não trouxe nenhum batimento'], heads };
  lista = [...lista].sort((a, b) => a.epoca - b.epoca);
  let chave;
  try { chave = await crypto.subtle.importKey('spki', b64(chaveSpkiB64), { name: 'Ed25519' }, false, ['verify']); }
  catch { return { problemas: ['este ambiente não confere Ed25519 ou a chave fixada é inválida'], heads }; }
  let anterior = null;
  for (const b of lista) {
    let p;
    try { p = JSON.parse(b.proposta); } catch { problemas.push(`época ${b.epoca}: proposta ilegível`); anterior = null; continue; }
    if (p.epoca !== b.epoca) problemas.push(`época ${b.epoca}: a proposta é de outra época`);
    let ok = false;
    try { ok = await crypto.subtle.verify({ name: 'Ed25519' }, chave, hexBytes(b.assinatura), new TextEncoder().encode(DOMINIO + b.proposta)); } catch { ok = false; }
    if (!ok) problemas.push(`época ${b.epoca}: a assinatura NÃO confere com a chave do grupo`);
    if (anterior !== null && p.anterior !== anterior) problemas.push(`época ${b.epoca}: não aponta para o batimento anterior (histórico alterado ou batimento removido)`);
    anterior = await sha256(b.proposta + '|' + b.assinatura);
    heads.set(b.epoca, anterior);
  }
  // FALHA FECHADA: hora ausente, ilegível ou no futuro é problema, nunca "tudo bem" (NaN nunca pode passar como fresco)
  let emitido = NaN;
  try { emitido = Date.parse(JSON.parse(lista[lista.length - 1].proposta).emitidoEm); } catch { /* fica NaN */ }
  if (!Number.isFinite(emitido)) problemas.push('o último batimento não traz uma hora de emissão válida');
  else {
    const idade = agoraMs - emitido;
    if (idade < -60_000) problemas.push('o último batimento tem hora de emissão no futuro');
    else if (idade > maxIdadeMs) problemas.push(`o último batimento assinado tem ${Math.round(idade / 60000)} min (esperado a cada 5): as sentinelas pararam`);
  }
  return { problemas, heads };
}

/** Só os problemas ([] = tudo certo). */
export async function conferir(lista, chaveSpkiB64, agoraMs = Date.now(), maxIdadeMs = 15 * 60_000) {
  return (await analisar(lista, chaveSpkiB64, agoraMs, maxIdadeMs)).problemas;
}

async function avisar(env, texto) {
  if (!env.HC_PING_URL) return;
  await fetch(`${env.HC_PING_URL.replace(/\/$/, '')}/fail`, { method: 'POST', body: texto.slice(0, 900) }).catch(() => undefined);
}

export default {
  async scheduled(_evento, env) {
    let problemas;
    try {
      const r = await fetch(`${env.API}/shield/batimentos?canal=principal&limite=60`, { headers: { Accept: 'application/json' } });
      if (!r.ok) problemas = [`a API pública respondeu ${r.status}`];
      else {
        const j = await r.json();
        problemas = await conferir(j?.data?.batimentos ?? [], env.CHAVE_GRUPO);
      }
    } catch (e) { problemas = [`sem resposta da API pública: ${e instanceof Error ? e.message : 'erro'}`]; }
    console.log(JSON.stringify({ vigia: problemas.length ? 'problema' : 'ok', problemas: problemas.slice(0, 3) })); // visível em `wrangler tail`
    if (problemas.length) await avisar(env, `Vigia de fora: ${problemas.slice(0, 3).join(' | ')}`);
  },
  fetch() { return new Response('nao encontrado', { status: 404 }); },
};
