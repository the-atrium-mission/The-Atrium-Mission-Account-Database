/**
 * Admin panel — behind Cloudflare Access.
 *
 * DESIGN CONSTRAINT, load-bearing:
 *
 * This panel CANNOT read a user's email address. Not "does not by default" —
 * there is no code path here that decrypts email_enc, and none should ever be
 * added. The whole point of envelope-encrypting emails is that no single
 * compromised credential exposes the user list. An admin UI with a "view
 * emails" button would make that encryption decorative: one stolen session and
 * the attacker has everything.
 *
 * If a real need arises to contact everyone, that is a batch job run
 * deliberately with its own key access and its own audit trail — not a screen
 * that can be left open on an unlocked laptop.
 *
 * What this panel does expose:
 *   - aggregate counts (signups, cohort interest, weekly trend)
 *   - handles, which are public by definition
 *   - invite issuance and redemption stats
 *   - invite generation
 *
 * Moving invite generation here is a security IMPROVEMENT over the CLI script:
 * INVITE_HMAC_PEPPER stays inside Cloudflare and never touches a workstation.
 */

import { hmacHex, isoWeek } from './crypto';
import { generateCode, normalizeCode } from './invites';

const MAX_BATCH = 200;

export async function adminStats(db: D1Database) {
  const [totals, weekly, invites] = await Promise.all([
    db
      .prepare(
        `SELECT COUNT(*) AS signups,
                SUM(founding_circle) AS founding,
                SUM(mycelium_host)   AS hosts
         FROM pre_alpha_signups`,
      )
      .first(),
    db
      .prepare(
        `SELECT created_week AS week, COUNT(*) AS n
         FROM pre_alpha_signups GROUP BY created_week ORDER BY created_week DESC LIMIT 12`,
      )
      .all(),
    db.prepare('SELECT note, issued, redeemed FROM invite_stats ORDER BY note').all(),
  ]);

  return {
    signups: Number((totals as any)?.signups ?? 0),
    founding: Number((totals as any)?.founding ?? 0),
    hosts: Number((totals as any)?.hosts ?? 0),
    weekly: weekly.results ?? [],
    invites: invites.results ?? [],
  };
}

/** Handles only. No email column is selected, deliberately. */
export async function adminHandles(db: D1Database, limit = 100, offset = 0) {
  const rows = await db
    .prepare(
      `SELECT handle_display, founding_circle, mycelium_host, created_week
       FROM pre_alpha_signups
       ORDER BY id DESC LIMIT ? OFFSET ?`,
    )
    .bind(Math.min(limit, 200), Math.max(offset, 0))
    .all();
  return rows.results ?? [];
}

/**
 * Mint a batch of invite codes.
 *
 * Plaintext codes are returned to the caller ONCE and never stored. Only the
 * HMAC goes to D1, so a database compromise yields no usable invites.
 */
export async function adminMintInvites(
  db: D1Database,
  pepper: string,
  count: number,
  note: string,
): Promise<{ codes: string[] } | { error: string }> {
  if (!Number.isInteger(count) || count < 1 || count > MAX_BATCH) {
    return { error: `Count must be between 1 and ${MAX_BATCH}.` };
  }
  if (!/^[a-z0-9._-]{1,40}$/i.test(note)) {
    return { error: 'Cohort label: letters, numbers, dot, dash, underscore. Max 40.' };
  }

  const week = isoWeek();
  const codes: string[] = [];
  const seen = new Set<string>();
  while (seen.size < count) {
    const c = generateCode();
    if (!seen.has(c)) { seen.add(c); codes.push(c); }
  }

  const stmts = [];
  for (const code of codes) {
    const norm = normalizeCode(code);
    if (!norm) return { error: 'Internal code generation fault.' };
    const hash = await hmacHex('invite', norm, pepper);
    stmts.push(
      db
        .prepare('INSERT INTO invite_codes (code_hash, issued_week, note) VALUES (?, ?, ?)')
        .bind(hash, week, note),
    );
  }

  // One transaction: either every code in the batch is redeemable, or none is.
  // A partial batch would mean handing out codes that silently do not work.
  await db.batch(stmts);

  return { codes };
}

/* ------------------------------------------------------------------ */

export function adminPage(email: string): string {
  return `<!DOCTYPE html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Admin — The Atrium Mission</title>
<meta name="robots" content="noindex,nofollow">
<style>
:root{--bg:#07100d;--surface:#0B1712;--line:#17251E;--amber:#E8920A;--dim:#7A4A06;
--text:#E6E4DF;--muted:#6E8078;--danger:#C4553D;
--mono:ui-monospace,SFMono-Regular,Menlo,monospace;--sans:system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);
font-family:var(--sans);font-size:15px;line-height:1.6}
.wrap{max-width:940px;margin:0 auto;padding:36px 22px 80px}
header{display:flex;justify-content:space-between;align-items:baseline;
border-bottom:1px solid var(--line);padding-bottom:18px;margin-bottom:32px;flex-wrap:wrap;gap:10px}
h1{font-size:19px;margin:0;letter-spacing:-.01em}
.who{font-family:var(--mono);font-size:12px;color:var(--muted)}
h2{font-family:var(--mono);font-size:11px;letter-spacing:.16em;text-transform:uppercase;
color:var(--muted);margin:38px 0 14px;font-weight:400}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px}
.stat{background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:16px 18px}
.stat .n{font-family:var(--mono);font-size:27px;color:var(--amber);line-height:1.1}
.stat .l{font-size:12px;color:var(--muted);margin-top:5px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-family:var(--mono);font-size:10px;letter-spacing:.13em;
text-transform:uppercase;color:var(--muted);font-weight:400;padding:9px 10px;
border-bottom:1px solid var(--line)}
td{padding:9px 10px;border-bottom:1px solid rgba(23,37,30,.55);font-family:var(--mono);font-size:12.5px}
.tag{display:inline-block;font-size:10px;padding:1px 6px;border-radius:2px;
border:1px solid var(--dim);color:var(--amber);margin-right:4px}
.panel{background:var(--surface);border:1px solid var(--line);border-radius:4px;padding:20px}
label{display:block;font-family:var(--mono);font-size:10px;letter-spacing:.13em;
text-transform:uppercase;color:var(--muted);margin-bottom:7px}
input{background:var(--bg);border:1px solid var(--line);border-radius:3px;color:var(--text);
font-family:var(--mono);font-size:14px;padding:10px 12px;width:100%;outline:none}
input:focus{border-color:var(--amber)}
.row{display:flex;gap:14px;flex-wrap:wrap}.row>div{flex:1;min-width:150px}
button{background:var(--amber);color:#0A0604;border:0;border-radius:3px;padding:11px 20px;
font-family:var(--mono);font-size:12px;letter-spacing:.12em;text-transform:uppercase;
cursor:pointer;margin-top:16px}
button:disabled{opacity:.4;cursor:not-allowed}
.codes{margin-top:18px;background:var(--bg);border:1px solid var(--dim);border-radius:3px;
padding:16px;font-family:var(--mono);font-size:14px;line-height:2;color:var(--amber);
white-space:pre-wrap;word-break:break-all;display:none}
.codes.on{display:block}
.warn{background:rgba(196,85,61,.07);border:1px solid rgba(196,85,61,.3);border-radius:3px;
padding:11px 14px;font-size:13px;color:#E0917E;margin-top:14px;display:none}
.warn.on{display:block}
.note{font-size:12.5px;color:var(--muted);margin-top:12px}
.muted{color:var(--muted)}
</style></head><body><div class="wrap">
<header>
  <h1>Phase 0.5 &middot; Admin</h1>
  <span class="who">${email.replace(/[<>&"]/g, '')}</span>
</header>

<h2>Overview</h2>
<div class="grid" id="stats"><div class="stat"><div class="n">&middot;</div><div class="l">loading</div></div></div>

<h2>Mint invite codes</h2>
<div class="panel">
  <div class="row">
    <div><label for="n">How many</label><input id="n" type="number" value="25" min="1" max="200"></div>
    <div><label for="note">Cohort label</label><input id="note" value="spirit2.0-batch1" maxlength="40"></div>
  </div>
  <button id="mint">Generate</button>
  <div class="warn" id="warn"></div>
  <div class="codes" id="codes"></div>
  <p class="note">Codes are shown once and are not stored anywhere. Only their hashes reach the database. Copy them before leaving this page.</p>
</div>

<h2>Invite batches</h2>
<table><thead><tr><th>Cohort</th><th>Issued</th><th>Redeemed</th><th>Remaining</th></tr></thead>
<tbody id="inv"><tr><td colspan="4" class="muted">loading</td></tr></tbody></table>

<h2>Reserved handles</h2>
<table><thead><tr><th>Handle</th><th>Interest</th><th>Week</th></tr></thead>
<tbody id="handles"><tr><td colspan="3" class="muted">loading</td></tr></tbody></table>
<p class="note">Email addresses are encrypted and cannot be read from this panel. That is deliberate, not a missing feature.</p>

</div><script>
function esc(s){return String(s).replace(/[<>&"]/g,'')}
fetch('/admin/api/stats').then(r=>r.json()).then(d=>{
  document.getElementById('stats').innerHTML =
    '<div class="stat"><div class="n">'+d.signups+'</div><div class="l">Handles reserved</div></div>'+
    '<div class="stat"><div class="n">'+d.founding+'</div><div class="l">Founding Circle</div></div>'+
    '<div class="stat"><div class="n">'+d.hosts+'</div><div class="l">Mycelium hosts</div></div>';
  var inv = d.invites.length ? d.invites.map(function(i){
    return '<tr><td>'+esc(i.note)+'</td><td>'+i.issued+'</td><td>'+i.redeemed+
           '</td><td>'+(i.issued-i.redeemed)+'</td></tr>'; }).join('')
    : '<tr><td colspan="4" class="muted">none yet</td></tr>';
  document.getElementById('inv').innerHTML = inv;
});
fetch('/admin/api/handles').then(r=>r.json()).then(rows=>{
  document.getElementById('handles').innerHTML = rows.length ? rows.map(function(r){
    var t='';
    if(r.founding_circle) t+='<span class="tag">FC</span>';
    if(r.mycelium_host) t+='<span class="tag">HOST</span>';
    return '<tr><td>@'+esc(r.handle_display)+'</td><td>'+(t||'<span class="muted">—</span>')+
           '</td><td class="muted">'+r.created_week+'</td></tr>'; }).join('')
    : '<tr><td colspan="3" class="muted">no reservations yet</td></tr>';
});
document.getElementById('mint').onclick = function(){
  var btn=this, warn=document.getElementById('warn'), out=document.getElementById('codes');
  warn.className='warn'; btn.disabled=true; btn.textContent='Generating…';
  fetch('/admin/api/invites',{method:'POST',headers:{'content-type':'application/json'},
    body:JSON.stringify({count:Number(document.getElementById('n').value),
                         note:document.getElementById('note').value.trim()})})
  .then(r=>r.json()).then(function(d){
    btn.disabled=false; btn.textContent='Generate';
    if(d.error){ warn.textContent=d.error; warn.className='warn on'; return; }
    out.textContent=d.codes.join('\\n'); out.className='codes on';
  }).catch(function(){ btn.disabled=false; btn.textContent='Generate';
    warn.textContent='Request failed.'; warn.className='warn on'; });
};
</script></body></html>`;
}
