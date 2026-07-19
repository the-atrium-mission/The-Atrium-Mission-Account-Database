/**
 * The /accounts signup page.
 *
 * Served by this Worker rather than the main site so the form and the endpoint
 * it posts to are versioned, reviewed, and audited as one unit. A form that
 * collects an email under a privacy promise should not be able to drift out of
 * sync with the code that receives it.
 *
 * Self-contained: no build step, no framework, no external JS.
 */

export function accountsPage(turnstileSiteKey: string): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Reserve your handle — The Atrium Mission</title>
<meta name="description" content="Closed alpha handle reservation for The Atrium Mission.">
<meta name="robots" content="noindex, nofollow">
<meta name="referrer" content="no-referrer">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Fraunces:opsz,wght@9..144,300;9..144,400&family=JetBrains+Mono:wght@400;500&family=Manrope:wght@400;500;600&display=swap" rel="stylesheet">
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
<style>
:root{
  --bg:#07100d;
  --surface:#0B1712;
  --line:#17251E;
  --amber:#E8920A;
  --amber-dim:#7A4A06;
  --text:#E6E4DF;
  --muted:#6E8078;
  --danger:#C4553D;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,monospace;
  --sans:'Manrope',system-ui,-apple-system,sans-serif;
  --display:'Fraunces','Iowan Old Style',Georgia,serif;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{
  background:var(--bg);
  color:var(--text);
  font-family:var(--sans);
  font-size:16px;
  line-height:1.6;
  -webkit-font-smoothing:antialiased;
  min-height:100vh;
}
/* Ambient warmth. Two offset radials so the amber reads as light in a room
   rather than a flat accent colour on black. */
body::before{
  content:'';position:fixed;inset:0;pointer-events:none;z-index:0;
  background:
    radial-gradient(680px 420px at 12% -8%, rgba(232,146,10,.055), transparent 70%),
    radial-gradient(520px 520px at 105% 108%, rgba(122,74,6,.075), transparent 70%);
}
main{position:relative;z-index:1;max-width:560px;margin:0 auto;padding:56px 24px 96px}

/* ---- masthead ---- */
.mast{display:flex;align-items:center;gap:12px;margin-bottom:64px}
.mark{width:26px;height:26px;flex:none}
.mast-name{font-family:var(--mono);font-size:12px;letter-spacing:.16em;text-transform:uppercase;color:var(--muted)}
.mast a{color:inherit;text-decoration:none}
.mast a:hover{color:var(--amber)}

/* ---- header ---- */
.eyebrow{
  font-family:var(--mono);font-size:11px;letter-spacing:.2em;text-transform:uppercase;
  color:var(--amber);margin:0 0 20px;display:flex;align-items:center;gap:10px;
}
.eyebrow::after{content:'';height:1px;flex:1;background:linear-gradient(90deg,var(--amber-dim),transparent)}
h1{
  font-family:var(--display);font-weight:300;font-size:clamp(30px,6vw,42px);
  line-height:1.15;margin:0 0 18px;letter-spacing:-.01em;
}
.lede{color:var(--muted);margin:0 0 8px;max-width:46ch}
.lede strong{color:var(--text);font-weight:500}

/* ---- form ---- */
form{margin-top:48px}
.field{margin-bottom:32px}
label{
  display:block;font-family:var(--mono);font-size:11px;letter-spacing:.14em;
  text-transform:uppercase;color:var(--muted);margin-bottom:10px;
}
.req{color:var(--amber-dim)}
.hint{font-size:13px;color:var(--muted);margin-top:8px;line-height:1.5}

.control{
  display:flex;align-items:center;gap:0;
  background:var(--surface);border:1px solid var(--line);border-radius:3px;
  transition:border-color .18s ease, box-shadow .18s ease;
}
.control:focus-within{border-color:var(--amber);box-shadow:0 0 0 3px rgba(232,146,10,.1)}
.control.is-bad{border-color:var(--danger)}
input[type=text],input[type=email]{
  flex:1;min-width:0;background:none;border:0;outline:none;color:var(--text);
  font-family:var(--sans);font-size:16px;padding:14px 14px;
}
input::placeholder{color:#3F5049}

/* Signature: the handle reads as an identity being claimed, not a text field.
   The @ is part of the chrome, so what you type is exactly what you get. */
.at{
  font-family:var(--mono);font-size:16px;color:var(--amber);
  padding:14px 0 14px 14px;user-select:none;
}
#handle{font-family:var(--mono);padding-left:2px;letter-spacing:.01em}

/* Invite code: wide tracking + auto-grouping. The alphabet was chosen so this
   can be retyped off a screen without ambiguity; the spacing should show it. */
#invite{font-family:var(--mono);letter-spacing:.22em;text-transform:uppercase}

.status{
  font-family:var(--mono);font-size:11px;letter-spacing:.1em;text-transform:uppercase;
  padding:0 14px;white-space:nowrap;color:var(--muted);
}
.status.ok{color:var(--amber)}
.status.no{color:var(--danger)}
.status .dot{
  display:inline-block;width:5px;height:5px;border-radius:50%;
  background:currentColor;margin-right:6px;vertical-align:middle;
}
.status.busy .dot{animation:pulse 1.1s ease-in-out infinite}
@keyframes pulse{0%,100%{opacity:.25}50%{opacity:1}}

/* ---- checkboxes ---- */
.check{display:flex;gap:12px;align-items:flex-start;margin-bottom:16px;cursor:pointer}
.check input{
  appearance:none;width:17px;height:17px;flex:none;margin:3px 0 0;
  border:1px solid var(--line);border-radius:2px;background:var(--surface);
  cursor:pointer;position:relative;transition:all .16s ease;
}
.check input:checked{background:var(--amber);border-color:var(--amber)}
.check input:checked::after{
  content:'';position:absolute;left:5px;top:1px;width:4px;height:9px;
  border:solid var(--bg);border-width:0 2px 2px 0;transform:rotate(42deg);
}
.check input:focus-visible{outline:2px solid var(--amber);outline-offset:2px}
.check-body{font-size:15px}
.check-sub{display:block;font-size:13px;color:var(--muted);margin-top:2px}

.optional-group{border-top:1px solid var(--line);padding-top:28px;margin-top:36px}
.group-title{
  font-family:var(--mono);font-size:11px;letter-spacing:.14em;text-transform:uppercase;
  color:var(--muted);margin:0 0 18px;
}

textarea{
  width:100%;background:var(--surface);border:1px solid var(--line);border-radius:3px;
  color:var(--text);font-family:var(--sans);font-size:15px;padding:14px;
  outline:none;resize:vertical;min-height:88px;line-height:1.55;
  transition:border-color .18s ease, box-shadow .18s ease;
}
textarea:focus{border-color:var(--amber);box-shadow:0 0 0 3px rgba(232,146,10,.1)}
.count{font-family:var(--mono);font-size:11px;color:var(--muted);text-align:right;margin-top:6px}

/* ---- submit ---- */
button[type=submit]{
  width:100%;margin-top:36px;padding:16px;
  background:var(--amber);color:#0A0604;border:0;border-radius:3px;
  font-family:var(--mono);font-size:13px;letter-spacing:.14em;text-transform:uppercase;
  font-weight:500;cursor:pointer;transition:opacity .16s ease, transform .16s ease;
}
button[type=submit]:hover:not(:disabled){opacity:.9}
button[type=submit]:active:not(:disabled){transform:translateY(1px)}
button[type=submit]:disabled{opacity:.35;cursor:not-allowed}
button:focus-visible{outline:2px solid var(--amber);outline-offset:3px}

.formerror{
  margin-top:20px;padding:13px 15px;border-radius:3px;
  border:1px solid rgba(196,85,61,.35);background:rgba(196,85,61,.07);
  color:#E0917E;font-size:14px;
}
.formerror:empty{display:none}
.cf{margin-top:24px}

/* ---- footer notes ---- */
.notes{
  margin-top:56px;padding-top:28px;border-top:1px solid var(--line);
  font-size:13px;color:var(--muted);line-height:1.65;
}
.notes p{margin:0 0 12px}
.notes p:last-child{margin:0}
.notes b{color:var(--text);font-weight:500}

/* ---- done state ---- */
.done{display:none;padding-top:8px}
.done.on{display:block;animation:rise .5s cubic-bezier(.16,1,.3,1)}
@keyframes rise{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:none}}
.done h2{font-family:var(--display);font-weight:300;font-size:30px;margin:0 0 16px}
.claimed{
  font-family:var(--mono);font-size:19px;color:var(--amber);
  background:var(--surface);border:1px solid var(--amber-dim);border-radius:3px;
  padding:16px 18px;margin:24px 0;word-break:break-all;
}
@media (prefers-reduced-motion:reduce){
  *{animation:none !important;transition:none !important}
}
</style>
</head>
<body>
<main>
  <div class="mast">
    <svg class="mark" viewBox="0 0 64 64" fill="none" aria-hidden="true">
      <rect x="5" y="5" width="54" height="54" rx="12" stroke="#E8920A" stroke-width="6"/>
      <path d="M20 44 L32 20 L44 44 M25 37 L39 37" stroke="#E8920A" stroke-width="6"
            stroke-linecap="round" stroke-linejoin="round"/>
    </svg>
    <span class="mast-name"><a href="https://theatriummission.com">The Atrium Mission</a></span>
  </div>

  <section id="formwrap">
    <p class="eyebrow">Phase 0.5 &middot; Closed alpha</p>
    <h1>Reserve your handle.</h1>
    <p class="lede">You need an invite code to be here. Your handle is held for you; <strong>the account itself comes later</strong>, when the platform opens.</p>

    <form id="signup" novalidate>
      <div class="field">
        <label for="invite">Invite code <span class="req">*</span></label>
        <div class="control" id="c-invite">
          <input id="invite" name="invite" type="text" inputmode="latin"
                 placeholder="XXXX-XXXX-XXXX" autocomplete="off" spellcheck="false"
                 maxlength="14" required>
        </div>
        <p class="hint">From the email that sent you here. Case and hyphens don't matter.</p>
      </div>

      <div class="field">
        <label for="handle">Handle <span class="req">*</span></label>
        <div class="control" id="c-handle">
          <span class="at" aria-hidden="true">@</span>
          <input id="handle" name="handle" type="text" placeholder="yourhandle"
                 autocomplete="off" spellcheck="false" autocapitalize="off"
                 maxlength="20" required aria-describedby="handle-status">
          <span class="status" id="handle-status" role="status" aria-live="polite"></span>
        </div>
        <p class="hint">3&ndash;20 characters. Letters, numbers, underscores.</p>
      </div>

      <div class="field">
        <label for="email">Email <span class="req">*</span></label>
        <div class="control" id="c-email">
          <input id="email" name="email" type="email" placeholder="you@example.com"
                 autocomplete="email" maxlength="254" required>
        </div>
        <p class="hint">Encrypted at rest. Used to reach you when the alpha opens, and nothing else.</p>
      </div>

      <label class="check" for="age">
        <input type="checkbox" id="age" required>
        <span class="check-body">I am 13 or older.
          <span class="check-sub">We don't ask for your date of birth.</span>
        </span>
      </label>

      <div class="optional-group">
        <p class="group-title">Optional</p>

        <label class="check" for="fc">
          <input type="checkbox" id="fc">
          <span class="check-body">Founding Circle
            <span class="check-sub">Help shape the rules before the platform opens.</span>
          </span>
        </label>

        <label class="check" for="mh">
          <input type="checkbox" id="mh">
          <span class="check-body">Run a Mycelium node
            <span class="check-sub">Contribute storage from a home server or homelab.</span>
          </span>
        </label>

        <div class="field" style="margin-top:26px">
          <label for="notes">Why you want in</label>
          <textarea id="notes" maxlength="1000" placeholder="Optional."></textarea>
          <div class="count"><span id="ct">0</span>/1000</div>
        </div>
      </div>

      <div class="cf cf-turnstile" data-sitekey="${turnstileSiteKey}" data-theme="dark"></div>

      <button type="submit" id="go">Reserve handle</button>
      <div class="formerror" id="err" role="alert"></div>
    </form>

    <div class="notes">
      <p><b>What this does.</b> Holds your handle and records that you're interested. That's the whole thing.</p>
      <p><b>What we store.</b> Your handle, an encrypted copy of your email, your two checkboxes, and the week you signed up. No IP address, no device information, no exact timestamp.</p>
      <p><b>What this isn't.</b> Not an account. There's no password yet and no way to log in. You'll set that up when the alpha opens.</p>
    </div>
  </section>

  <section class="done" id="done">
    <p class="eyebrow">Reserved</p>
    <h2>Your handle is held.</h2>
    <div class="claimed" id="claimed"></div>
    <p class="lede">We'll email you when the alpha opens, with a link to set a password and finish your account. Your invite code is now spent.</p>
    <div class="notes">
      <p>Nothing else happens until then. No newsletter, no drip campaign.</p>
    </div>
  </section>
</main>

<script>
(function(){
  var invite = document.getElementById('invite');
  var handle = document.getElementById('handle');
  var email  = document.getElementById('email');
  var notes  = document.getElementById('notes');
  var ct     = document.getElementById('ct');
  var status = document.getElementById('handle-status');
  var err    = document.getElementById('err');
  var go     = document.getElementById('go');
  var form   = document.getElementById('signup');

  /* Invite code: uppercase, strip separators, regroup in fours as you type.
     Caret is pushed to the end because grouping mid-string would otherwise
     drag it backwards on every fourth character. */
  invite.addEventListener('input', function(){
    var bare = invite.value.toUpperCase().replace(/[^0-9A-Z]/g,'').slice(0,12);
    var out = [];
    for (var i=0;i<bare.length;i+=4) out.push(bare.slice(i,i+4));
    invite.value = out.join('-');
  });

  notes.addEventListener('input', function(){ ct.textContent = String(notes.value.length); });

  /* Live availability. Debounced so a fast typist spends one request, not ten. */
  var timer = null, seq = 0;
  function setStatus(text, cls){
    status.className = 'status' + (cls ? ' ' + cls : '');
    status.innerHTML = text ? '<span class="dot"></span>' + text : '';
  }
  handle.addEventListener('input', function(){
    var v = handle.value.trim();
    document.getElementById('c-handle').classList.remove('is-bad');
    clearTimeout(timer);
    if (v.length < 3){ setStatus('',''); return; }
    setStatus('checking','busy');
    var mine = ++seq;
    timer = setTimeout(function(){
      fetch('/api/check-handle?h=' + encodeURIComponent(v))
        .then(function(r){ return r.json(); })
        .then(function(d){
          if (mine !== seq) return;          // a newer keystroke already won
          if (d.available) setStatus('available','ok');
          else { setStatus('taken','no'); document.getElementById('c-handle').classList.add('is-bad'); }
        })
        .catch(function(){ if (mine === seq) setStatus('',''); });
    }, 380);
  });

  function fail(msg){
    err.textContent = msg;
    go.disabled = false;
    go.textContent = 'Reserve handle';
  }

  form.addEventListener('submit', function(e){
    e.preventDefault();
    err.textContent = '';

    if (!document.getElementById('age').checked) return fail('Confirm you are 13 or older to continue.');
    if (!invite.value.trim())  return fail('Enter your invite code.');
    if (handle.value.trim().length < 3) return fail('Choose a handle of at least 3 characters.');
    if (!email.value.trim())   return fail('Enter your email address.');

    go.disabled = true;
    go.textContent = 'Reserving\\u2026';

    var tokenEl = document.querySelector('[name="cf-turnstile-response"]');

    fetch('/api/signup', {
      method:'POST',
      headers:{'content-type':'application/json'},
      body: JSON.stringify({
        invite_code: invite.value.trim(),
        handle: handle.value.trim(),
        email: email.value.trim(),
        age_confirmed: true,
        founding_circle: document.getElementById('fc').checked,
        mycelium_host: document.getElementById('mh').checked,
        notes: notes.value.trim(),
        turnstile_token: tokenEl ? tokenEl.value : ''
      })
    })
    .then(function(r){ return r.json().then(function(d){ return {s:r.status, d:d}; }); })
    .then(function(res){
      if (res.d && res.d.ok){
        document.getElementById('claimed').textContent = '@' + handle.value.trim();
        document.getElementById('formwrap').style.display = 'none';
        document.getElementById('done').classList.add('on');
        window.scrollTo({top:0, behavior:'smooth'});
        return;
      }
      if (res.d && res.d.needs_turnstile && window.turnstile){
        window.turnstile.reset();
        return fail('Complete the verification below and try again.');
      }
      fail((res.d && res.d.error) || 'Something went wrong. Try again.');
    })
    .catch(function(){ fail('Could not reach the server. Check your connection and try again.'); });
  });
})();
</script>
</body>
</html>`;
}
