#!/usr/bin/env python3
"""Interface web locale pour l'analyse Sentinelle."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

from flask import Flask, render_template_string, request
from werkzeug.utils import secure_filename

from sentinelle import analyze

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 300 * 1024 * 1024

HTML = r'''<!doctype html>
<html lang="fr"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinelle — Analyse réseau</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=Manrope:wght@400;500;600;700;800&display=swap');
:root{--bg:#0a1114;--panel:#111c20;--line:#233238;--muted:#91a3a6;--text:#e8f0ed;--mint:#72e0ba;--amber:#ffc66d;--red:#ff7f76;--blue:#8fc9e9}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 78% 0%,#18302c 0,transparent 32%),var(--bg);color:var(--text);font-family:Manrope,system-ui,sans-serif;min-height:100vh}
.wrap{max-width:1060px;margin:0 auto;padding:38px 25px 68px}.top{display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line);padding-bottom:19px}.brand{display:flex;align-items:center;gap:12px;font-weight:800;letter-spacing:.03em}.logo{width:37px;height:37px;display:grid;place-items:center;border:1px solid #3a6559;border-radius:12px;color:var(--mint);font-size:20px;background:#142822}.local{font:11px 'DM Mono',monospace;color:var(--muted);border:1px solid var(--line);padding:8px 11px;border-radius:99px}.local i{display:inline-block;width:7px;height:7px;background:var(--mint);border-radius:50%;margin-right:7px}
.hero{padding:47px 0 30px;max-width:750px}.eyebrow{color:var(--mint);font:11px 'DM Mono',monospace;letter-spacing:.16em;text-transform:uppercase}.hero h1{font-size:clamp(32px,5vw,53px);line-height:1.08;letter-spacing:-.05em;margin:13px 0}.hero p{font-size:15px;line-height:1.75;color:#aab9b8;max-width:650px;margin:0}
.upload{background:linear-gradient(145deg,#142125,#10191d);border:1px solid #2b4145;border-radius:18px;padding:22px;box-shadow:0 18px 65px #0003}.drop{position:relative;border:1px dashed #426158;border-radius:13px;min-height:165px;display:flex;flex-direction:column;align-items:center;justify-content:center;text-align:center;padding:24px;transition:.18s;background:#0c1718}.drop:hover,.drop.over{border-color:var(--mint);background:#11201e}.upload-icon{font-size:28px;color:var(--mint);margin-bottom:9px}.drop strong{font-size:15px}.drop span{font-size:12px;color:var(--muted);margin-top:7px}.drop input{position:absolute;inset:0;width:100%;height:100%;opacity:0;cursor:pointer}.fileline{display:flex;justify-content:space-between;align-items:center;gap:16px;margin-top:17px}.filename{color:var(--muted);font-size:12px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.button{border:0;border-radius:9px;padding:12px 18px;background:var(--mint);color:#0b1715;font:700 13px Manrope,sans-serif;cursor:pointer;transition:.15s}.button:hover{background:#98f0d0;transform:translateY(-1px)}.button:disabled{opacity:.55;cursor:wait}
.error{margin:18px 0;background:#301b1b;border:1px solid #72413e;color:#ffc7c2;padding:14px 16px;border-radius:10px;font-size:13px}.result{margin-top:36px}.sectionhead{display:flex;justify-content:space-between;align-items:end;margin-bottom:14px;gap:18px}.sectionhead h2{margin:0;font-size:22px;letter-spacing:-.03em}.meta{font:11px 'DM Mono',monospace;color:var(--muted)}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:19px}.stat,.card{background:var(--panel);border:1px solid var(--line);border-radius:13px}.stat{padding:15px 17px}.stat label{display:block;color:var(--muted);font:10px 'DM Mono',monospace;text-transform:uppercase;letter-spacing:.1em}.stat b{display:block;margin-top:7px;font-size:20px}.verdict{padding:17px 19px;border-radius:13px;margin-bottom:15px;border:1px solid var(--line);background:#121d20;display:flex;gap:12px;align-items:center}.verdict .mark{font-size:20px}.verdict strong{font-size:14px}.verdict p{margin:3px 0 0;color:var(--muted);font-size:12px;line-height:1.6}.ipbox{padding:16px 18px;margin-bottom:15px}.iphead{font-weight:700;font-size:13px;margin-bottom:10px}.ips{display:flex;flex-wrap:wrap;gap:8px}.ip{font:12px 'DM Mono',monospace;color:var(--blue);background:#12252b;border:1px solid #24424a;border-radius:7px;padding:7px 9px}.findings{display:grid;gap:10px}.finding{padding:15px 17px;display:grid;grid-template-columns:8px 1fr;gap:12px}.dot{width:8px;height:8px;border-radius:50%;margin-top:5px}.dot.high{background:var(--red);box-shadow:0 0 12px #ff7f7666}.dot.medium{background:var(--amber)}.dot.info{background:var(--blue)}.findingtop{display:flex;justify-content:space-between;gap:12px;align-items:start}.finding h3{font-size:13px;margin:0}.badge{font:10px 'DM Mono',monospace;color:var(--muted);white-space:nowrap}.finding p{font-size:12px;line-height:1.65;color:#aab9b8;margin:6px 0}.evidence{font:10px 'DM Mono',monospace;color:#78908f;word-break:break-word}.empty{padding:25px;text-align:center;color:var(--mint);font-size:14px}.foot{border-top:1px solid var(--line);margin-top:29px;padding-top:17px;color:#708184;font-size:11px;line-height:1.7}.spinner{display:none;margin-right:7px;animation:spin 1s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
@media(max-width:620px){.wrap{padding:22px 15px 45px}.top{align-items:start}.hero{padding:36px 0 24px}.stats{gap:7px}.stat{padding:12px}.stat b{font-size:17px}.stat label{font-size:9px}.findingtop{display:block}.badge{display:inline-block;margin-top:6px}.fileline{align-items:stretch;flex-direction:column}.button{width:100%}}
</style></head><body><main class="wrap">
<header class="top"><div class="brand"><div class="logo">⌁</div><span>SENTINELLE</span></div><div class="local"><i></i>ANALYSE LOCALE</div></header>
<section class="hero"><div class="eyebrow">Investigation réseau · 01</div><h1>Repérez les signaux<br>qui sortent du trafic.</h1><p>Déposez une capture Wireshark. Sentinelle examine les flux, les ports et les requêtes DNS, puis met en évidence les adresses IP associées aux comportements suspects.</p></section>
<form class="upload" method="post" enctype="multipart/form-data" id="form"><div class="drop" id="drop"><div class="upload-icon">↥</div><strong>Déposez votre capture ici</strong><span>Formats pris en charge : .pcap, .pcapng · maximum 300 Mo</span><input type="file" name="capture" id="file" accept=".pcap,.pcapng,application/vnd.tcpdump.pcap,application/x-pcapng" required></div><div class="fileline"><div class="filename" id="filename">Aucun fichier sélectionné</div><button class="button" id="submit" type="submit"><span class="spinner" id="spinner">◌</span>Analyser la capture →</button></div></form>
{% if error %}<div class="error">{{ error }}</div>{% endif %}
{% if summary %}<section class="result" id="result"><div class="sectionhead"><div><div class="eyebrow">Rapport d'analyse</div><h2>{{ filename }}</h2></div><div class="meta">{{ summary.paquets_ip }} paquets IP</div></div>
<div class="stats"><div class="stat"><label>Paquets inspectés</label><b>{{ summary.paquets_ip }}</b></div><div class="stat"><label>Flux uniques</label><b>{{ summary.flux_uniques }}</b></div><div class="stat"><label>Indicateurs relevés</label><b>{{ summary.alertes }}</b></div></div>
{% if findings %}<div class="verdict"><div class="mark">{% if high_count %}⚠{% else %}◉{% endif %}</div><div><strong>{% if high_count %}Activité suspecte détectée{% else %}Indicateurs à examiner{% endif %}</strong><p>Les règles ont relevé {{ findings|length }} élément(s). Une alerte signale un comportement à vérifier et ne confirme pas à elle seule une compromission.</p></div></div>
<div class="card ipbox"><div class="iphead">Adresses IP citées dans les alertes</div><div class="ips">{% for ip in ips %}<span class="ip">{{ ip }}</span>{% endfor %}{% if not ips %}<span class="meta">Aucune adresse IP directement attribuée aux règles déclenchées.</span>{% endif %}</div></div>
<div class="findings">{% for f in findings %}<article class="card finding"><div class="dot {% if f.severity == 'ÉLEVÉ' %}high{% elif f.severity == 'MOYEN' %}medium{% else %}info{% endif %}"></div><div><div class="findingtop"><h3>{{ f.title }}</h3><span class="badge">{{ f.severity }} · {{ f.rule }}</span></div><p>{{ f.detail }}</p><div class="evidence">{% for key,value in f.evidence.items() %}{{ key }}: {{ value }}{% if not loop.last %} &nbsp;·&nbsp; {% endif %}{% endfor %}</div></div></article>{% endfor %}</div>
{% else %}<div class="card empty">✓ Aucun indicateur détecté par les règles activées.<p class="meta">Cela ne garantit pas l'absence de compromission.</p></div>{% endif %}
<div class="foot">Période UTC : {{ summary.debut_utc or 'non disponible' }} → {{ summary.fin_utc or 'non disponible' }}. L'analyse se limite aux champs visibles dans la capture et ne déchiffre pas TLS. Les résultats sont heuristiques.</div></section>{% endif %}
<footer class="foot">Sentinelle traite la capture temporairement sur cette machine et la supprime après l'analyse. Gardez en tête que les PCAP peuvent contenir des données sensibles.</footer>
</main><script>
const input=document.getElementById('file'),label=document.getElementById('filename'),drop=document.getElementById('drop');
input.addEventListener('change',()=>{label.textContent=input.files.length?input.files[0].name:'Aucun fichier sélectionné'});
for(const ev of ['dragenter','dragover'])drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.add('over')});
for(const ev of ['dragleave','drop'])drop.addEventListener(ev,e=>{e.preventDefault();drop.classList.remove('over')});
drop.addEventListener('drop',e=>{if(e.dataTransfer.files.length){input.files=e.dataTransfer.files;input.dispatchEvent(new Event('change'))}});
document.getElementById('form').addEventListener('submit',()=>{document.getElementById('submit').disabled=true;document.getElementById('spinner').style.display='inline-block';document.getElementById('submit').lastChild.textContent=' Analyse en cours…'});
</script></body></html>'''


@app.errorhandler(413)
def too_large(_error):
    return render_template_string(HTML, error="Fichier trop volumineux. La limite est de 300 Mo.", summary=None, findings=None), 413


@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "GET":
        return render_template_string(HTML, error=None, summary=None, findings=None)
    upload = request.files.get("capture")
    if not upload or not upload.filename:
        return render_template_string(HTML, error="Choisissez un fichier de capture.", summary=None, findings=None), 400
    filename = secure_filename(upload.filename)
    if Path(filename).suffix.lower() not in {".pcap", ".pcapng"}:
        return render_template_string(HTML, error="Format non pris en charge. Envoyez un fichier .pcap ou .pcapng.", summary=None, findings=None), 400
    try:
        with tempfile.TemporaryDirectory(prefix="sentinelle-") as tempdir:
            capture_path = Path(tempdir) / filename
            upload.save(capture_path)
            args = argparse.Namespace(
                tshark=os.environ.get("TSHARK_PATH"), timeout=300,
                port_scan_threshold=20, syn_threshold=100,
                dns_threshold=100, dns_chars_threshold=500,
                unusual_port_threshold=50,
            )
            findings, summary = analyze(capture_path, args)
    except (RuntimeError, OSError) as exc:
        return render_template_string(HTML, error=f"Analyse impossible : {exc}", summary=None, findings=None), 500

    # La page ne divulgue que les adresses explicitement reliées à une alerte.
    ips = set()
    for finding in findings:
        for key in ("source", "destination"):
            value = finding.evidence.get(key)
            if value:
                ips.add(str(value))
    high_count = sum(item.severity == "ÉLEVÉ" for item in findings)
    return render_template_string(HTML, error=None, findings=findings,
                                  summary=summary, filename=filename,
                                  ips=sorted(ips), high_count=high_count)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=int(os.environ.get("PORT", "5000")), debug=False)
