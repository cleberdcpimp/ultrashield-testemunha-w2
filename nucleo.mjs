// NÚCLEO DA TESTEMUNHA INDEPENDENTE (JS puro: roda em Cloudflare Worker, em Node e na página de status).
// Uma testemunha baixa a cadeia PÚBLICA de batimentos, confere tudo sozinha (assinatura do grupo, elos, frescor) e assina, com a SUA chave
// (Ed25519 comum, determinística: sem risco de reutilizar valor secreto), o compromisso "vi esta cabeça da cadeia nesta época".
// REGRA ATÔMICA anti-equivocação: nunca assina duas cabeças diferentes para a mesma época e nunca assina uma cadeia que não estenda a que já assinou.
// O estado (época, cabeça) é gravado ANTES de a assinatura sair: se cair no meio, no pior caso reemite a MESMA assinatura (Ed25519 é determinístico).
import { analisar } from './vigia.mjs';

export const DOMINIO_COSIGN = 'ultrashield-testemunha-v1\n';
const enc = (s) => new TextEncoder().encode(s);
const b64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const hexBytes = (h) => Uint8Array.from(h.match(/../g) ?? [], (x) => parseInt(x, 16));
const paraHex = (buf) => [...new Uint8Array(buf)].map((x) => x.toString(16).padStart(2, '0')).join('');

/** Texto canônico do compromisso (ordem de campos fixa). */
export const cosignCanonico = (c) => JSON.stringify({ v: 1, canal: c.canal, epoca: c.epoca, cabeca: c.cabeca, testemunha: c.testemunha });

/**
 * Decide o que fazer com a cadeia baixada.
 * @param estado {epoca, cabeca} | null  -> o último que ESTA testemunha assinou
 * @returns {acao: 'assinar'|'reemitir'|'recusar', motivo?, alerta?, cosign?, novoEstado?}
 */
export async function decidir({ estado, lista, chaveGrupo, canal, testemunha, agoraMs = Date.now(), maxIdadeMs = 15 * 60_000 }) {
  const { problemas, heads } = await analisar(lista, chaveGrupo, agoraMs, maxIdadeMs);
  if (problemas.length) return { acao: 'recusar', motivo: `a cadeia tem problemas: ${problemas.slice(0, 3).join(' | ')}`, alerta: 'cadeia_com_problema' };
  const ult = Math.max(...heads.keys());
  const cabeca = heads.get(ult);
  const cosign = { canal, epoca: ult, cabeca, testemunha };
  if (!estado) return { acao: 'assinar', cosign, novoEstado: { epoca: ult, cabeca } };
  if (ult < estado.epoca) return { acao: 'recusar', motivo: `a cadeia recuou (época ${ult} < ${estado.epoca} já assinada)`, alerta: 'recuo' };
  if (ult === estado.epoca) {
    return cabeca === estado.cabeca
      ? { acao: 'reemitir', cosign, novoEstado: estado }
      : { acao: 'recusar', motivo: `EQUIVOCAÇÃO: duas cabeças diferentes para a época ${ult}`, alerta: 'equivocacao' };
  }
  const h = heads.get(estado.epoca);
  if (h === undefined) return { acao: 'recusar', motivo: `a janela baixada não cobre a época ${estado.epoca} que já assinei: peça um limite maior`, alerta: 'janela' };
  if (h !== estado.cabeca) return { acao: 'recusar', motivo: `a cadeia NÃO estende a que assinei na época ${estado.epoca} (histórico reescrito)`, alerta: 'equivocacao' };
  return { acao: 'assinar', cosign, novoEstado: { epoca: ult, cabeca } };
}

/** Assina o compromisso com a chave PKCS#8 (base64) da testemunha. Devolve a assinatura em hex. */
export async function assinarCosign(cosign, chavePkcs8B64) {
  const chave = await crypto.subtle.importKey('pkcs8', b64(chavePkcs8B64), { name: 'Ed25519' }, false, ['sign']);
  return paraHex(await crypto.subtle.sign({ name: 'Ed25519' }, chave, enc(DOMINIO_COSIGN + cosignCanonico(cosign))));
}

/** Confere a assinatura de UMA testemunha com a chave pública (SPKI base64) dela. */
export async function verificarCosign(cosign, assinaturaHex, chavePublicaSpkiB64) {
  try {
    const chave = await crypto.subtle.importKey('spki', b64(chavePublicaSpkiB64), { name: 'Ed25519' }, false, ['verify']);
    return await crypto.subtle.verify({ name: 'Ed25519' }, chave, hexBytes(assinaturaHex), enc(DOMINIO_COSIGN + cosignCanonico(cosign)));
  } catch { return false; }
}

/**
 * Regra do VERIFICADOR: quantas testemunhas confirmam a cadeia que EU conferi.
 * @param heads Map época -> hash (calculado por quem verifica, nunca copiado da testemunha)
 * @param testemunhas [{id, chavePublica, cosign, assinatura}] (o que cada testemunha publicou)
 * @param ultimaEpoca época do último batimento que eu conferi; aceita cosign de até `folga` épocas atrás
 */
export async function contarTestemunhas(heads, ultimaEpoca, testemunhas, folga = 3) {
  const ok = [], falhas = [];
  for (const t of testemunhas) {
    const c = t.cosign;
    if (!c || !t.assinatura) { falhas.push({ id: t.id, motivo: 'sem cosign' }); continue; }
    if (c.testemunha !== t.id) { falhas.push({ id: t.id, motivo: 'cosign de outra testemunha' }); continue; }
    if (!(await verificarCosign(c, t.assinatura, t.chavePublica))) { falhas.push({ id: t.id, motivo: 'assinatura não confere' }); continue; }
    if (heads.get(c.epoca) !== c.cabeca) { falhas.push({ id: t.id, motivo: 'a cabeça assinada não é a da cadeia que eu conferi' }); continue; }
    if (c.epoca < ultimaEpoca - folga) { falhas.push({ id: t.id, motivo: 'cosign velho demais' }); continue; }
    ok.push(t.id);
  }
  return { confirmam: ok, falhas };
}
