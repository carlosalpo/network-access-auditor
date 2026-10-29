"""Static evidence projection. Reads saved results; no product execution or invented values."""
import csv
import hashlib
import html
import json
from collections import Counter
from pathlib import Path

P = Path(__file__).resolve().parents[1]
def read(path): return json.loads((P / path).read_text())
def sha(path): return hashlib.sha256((P / path).read_bytes()).hexdigest()
def esc(value):
    if isinstance(value, bool): value = str(value).lower()
    if isinstance(value, list): value = ', '.join(value) or '—'
    return html.escape(str(value))
def table(rows, cols):
    return '<table><thead><tr>' + ''.join(f'<th>{esc(label)}</th>' for key,label in cols) + '</tr></thead><tbody>' + ''.join('<tr>' + ''.join(f'<td>{esc(r[key])}</td>' for key,label in cols) + '</tr>' for r in rows) + '</tbody></table>'
def box(title, content): return f'<section><h2>{title}</h2>{content}</section>'
def pre(value): return '<pre>' + esc(value if isinstance(value,str) else json.dumps(value,indent=2)) + '</pre>'
def stat(value, label): return f'<div class="stat"><strong>{esc(value)}</strong><span>{label}</span></div>'
def note(text): return f'<p class="note">{text}</p>'

summary = read('outputs/summary.json')
run = read('logs/run.json')
audits = {}
verified = 0
for s in summary:
    case = s['case']
    if s['exit_code'] == 2:
        assert not (P/'outputs'/case).exists()
        continue
    d = read(f'outputs/{case}/audit.json'); audits[case] = d
    m = read(f'outputs/{case}/manifest.json')
    assert m['input_sha256'] == sha(f'sources/{case}.json')
    assert len(list((P/'outputs'/case).iterdir())) == 9
    for filename, metadata in m['files'].items():
        path = f'outputs/{case}/{filename}'
        assert sha(path) == metadata['sha256']
        assert (P/path).stat().st_size == metadata['bytes']
        verified += 1
    assert len(d['states']) == (d['counts']['groups']+1)*2*3 == 30
    assert sum(r['effective_states'] for r in d['rule_coverage']) + sum(s['decision']=='@default' for s in d['states']) == 30
    for filename,key in [('states.csv','states'),('rule-coverage.csv','rule_coverage'),('checks.csv','checks'),('endpoints.csv','endpoints'),('findings.csv','findings')]:
        rows = list(csv.DictReader((P/'outputs'/case/filename).open()))
        assert len(rows)==len(d[key])
        for row, original in zip(rows,d[key]):
            for field,value in row.items():
                expected = original[field]
                expected = ';'.join(expected) if isinstance(expected,list) else str(expected)
                if expected.lstrip().startswith(('=','+','-','@')): expected = "'"+expected
                assert value == expected, (case,filename,field)

assert '124 passed' in (P/'logs/pytest.stdout.log').read_text()
assert len(summary)==8 and verified==56
r = audits['risky-first-match']; expired=audits['expired-mab']; current=audits['current-mab']
counts=Counter(f['code'] for f in r['findings'])
risk=[f for f in r['findings'] if 'affected_states' in f['evidence']]
assert len(risk)==4 and counts['RULE_SHADOWED']==5 and counts['INTENT_MISMATCH']==4 and counts['MAB_EXCEPTION_MISSING']==2
assert r['counts']['findings']==15
assert expired['counts']['findings']==1 and current['counts']['findings']==0
assert expired['baseline']==current['baseline']==dict(standard_requires_dot1x=False,standard_requires_compliant=True)
assert audits['baseline']['counts']['findings']==0
verification=dict(scenarios=8,accepted_packages=7,files_per_package=9,artifact_hashes_verified=56,
                  csv_json_projections_verified=35,modeled_states_per_scenario=30,
                  first_match_coverage_reconciled=True,invalid_reference_output_exists=False,
                  repository_files_unchanged=run['repository_files_unchanged'])
(P/'logs/verification.json').write_text(json.dumps(verification,indent=2)+'\n')

css='''*{box-sizing:border-box}body{margin:0;background:#edf1f3;color:#172c3c;font:18px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}.page{max-width:1440px;margin:auto;padding:34px 44px 28px;background:#fff;min-height:960px}header{border-top:6px solid #203d50;padding-top:18px}.eyebrow{display:flex;justify-content:space-between;font-size:14px;font-weight:700;letter-spacing:.07em;text-transform:uppercase;color:#476174}.label{color:#9a351f}h1{font-size:39px;line-height:1.1;letter-spacing:-1.1px;margin:20px 0 10px}h2{font-size:20px;margin:0 0 12px}p{margin:9px 0}.sub{color:#526574;margin-bottom:22px}.stats{display:flex;border:1px solid #cdd7de;margin:20px 0;}.stat{flex:1;padding:16px 22px;border-right:1px solid #cdd7de}.stat:last-child{border:0}.stat strong{display:block;font-size:32px;line-height:1.2}.stat span{font-size:16px;color:#526574}section{margin:23px 0}table{width:100%;border-collapse:collapse;font-size:16px}th{text-align:left;background:#eaf0f4;font-size:13px;letter-spacing:.025em}th,td{padding:10px 12px;border-bottom:1px solid #d8e0e5}td{font-variant-numeric:tabular-nums}pre{font:16px/1.45 ui-monospace,SFMono-Regular,Consolas,monospace;background:#f1f5f7;padding:17px 20px;margin:0;white-space:pre-wrap;overflow-wrap:anywhere}.note{background:#fff5e8;border-left:4px solid #b77331;padding:13px 17px;font-size:16px}.two{display:grid;grid-template-columns:1fr 1fr;gap:25px}.two section{margin-top:15px}.sources{font:12px/1.55 ui-monospace,SFMono-Regular,monospace;color:#536a79;overflow-wrap:anywhere;margin-top:20px}footer{border-top:2px solid #c4d0d8;padding-top:13px;margin-top:20px;font-size:14px;color:#465d6d}footer b{color:#203d50}.meta{display:flex;justify-content:space-between;margin-top:9px;font-size:12px}code{font-family:ui-monospace,SFMono-Regular,monospace}.accent{color:#9a351f}'''
(P/'viewer/style.css').write_text(css)
pages=[]
def page(slug,title,subtitle,body,sources,selection):
    number=len(pages)+1
    source_html='<div class="sources">FUENTES · rutas relativas al paquete · SHA-256 abreviado (completo en manifest.json)<br>'+ '<br>'.join(esc(s)+' · '+sha(s)[:16] for s in sources)+'</div>'
    footer='<footer><b>Auditor OFFLINE · JSON NAC normalizado manualmente · ejemplos sintéticos.</b><br>Sin conexión, importación o emulación de ISE; sin autenticación ni enforcement real. Trust y access son declarados.<br>Estos resultados no prueban explotación ni certifican seguridad.<div class="meta"><span>Network Access Auditor · v0.1.0 · commit bf76b4bf12d0</span><span>Captura 2026-10-29 · America/Tegucigalpa · '+str(number)+'/5</span></div></footer>'
    content='<!doctype html><html lang="es"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>'+title+' | Network Access Auditor</title><link rel="stylesheet" href="style.css"><main class="page"><header><div class="eyebrow"><span>Network Access Auditor / Evidencia de ejecución</span><span class="label">Not product UI</span></div><h1>'+title+'</h1><p class="sub">'+subtitle+'</p></header>'+body+source_html+footer+'</main></html>'
    (P/'viewer'/f'{slug}.html').write_text(content)
    pages.append(dict(id=slug,viewer=f'viewer/{slug}.html',sources=sources,selection=selection))

f=next(f for f in risk if f['code']=='UNCLASSIFIED_INTERNAL_ACCESS')
w=f['evidence']['witnesses'][0]
body='<div class="stats">'+stat(r['counts']['findings'],'hallazgos del modelo')+stat(r['counts']['states'],'estados modelados')+stat('FAIL','gate: medium · exit 1')+'</div>'
body+=box('Cuatro riesgos agregados por decisión',table([dict(code=f['code'],severity=f['severity'],states=f['evidence']['affected_states']) for f in risk],[('code','Código literal'),('severity','Severidad'),('states','Estados afectados')]))
body+=note('15 hallazgos = 4 riesgos agregados + 5 reglas sombreadas + 4 discrepancias de intención + 2 excepciones MAB ausentes. Los estados afectados se solapan; no se suman como sesiones.')
body+=box('Testigo literal · UNCLASSIFIED_INTERNAL_ACCESS',table([w],[('group','group'),('trust','trust'),('method','method'),('posture','posture'),('decision','decision / ganadora'),('profile','profile'),('access','access')]))
body+=pre((P/'outputs/risky-first-match.log').read_text())
page('01-risk-witness','Una regla amplia gana primero','Escenario: risky-first-match · un testigo del modelo explica el acceso interno a unclassified.',body,['outputs/risky-first-match/audit.json','outputs/risky-first-match.log'],'Four findings with affected_states; first witness of UNCLASSIFIED_INTERNAL_ACCESS. Counts grouped by code. Raw scenario log.')

body=box('Orden y cobertura · risky-first-match',table(r['rule_coverage'],[('order','#'),('rule','Regla'),('potential_states','Potenciales'),('effective_states','Efectivos'),('shadowed_states','Sombreados'),('shadowed_by','Ganadoras anteriores')]))
body+=note('broad-first gana los 30 estados. Las cinco reglas siguientes tienen cero estados efectivos. La cobertura potencial no representa acceso adicional.')
shadow=audits['shadowed-rule']; target=next(x for x in shadow['rule_coverage'] if x['rule']=='unreachable-admin')
body+=box('Contraste independiente · shadowed-rule',table([target],[('rule','Regla'),('potential_states','Potenciales'),('effective_states','Efectivos'),('shadowed_states','Sombreados'),('shadowed_by','Ganadora anterior')]))
body+=box('Testigo literal de la regla sombreada',table(shadow['findings'][0]['evidence']['witnesses'],[('group','group'),('method','method'),('posture','posture'),('decision','decision'),('profile','profile'),('access','access')]))
body+=note('Dominio: (4 grupos + unclassified) × 2 métodos × 3 posturas = 30 estados. Exhaustivo solo en estas dimensiones; no cuenta sesiones ni prueba alcance real.')
page('02-rule-coverage','Qué regla gana; qué regla nunca llega','La evaluación conserva el orden y aplica únicamente la primera coincidencia habilitada.',body,['outputs/risky-first-match/audit.json','outputs/shadowed-rule/audit.json'],'All risky-first-match rule coverage rows with selected columns; unreachable-admin row and its witness with selected columns from shadowed-rule.')

rows=[]
for case in ['expired-mab','current-mab']:
    d=audits[case]; ep=next(x for x in d['endpoints'] if x['id']=='legacy-device')
    rows.append(dict(case=case,assessment_date=d['assessment_date'],findings=d['counts']['findings'],gate='FAIL' if d['gate']['failed'] else 'PASS',**ep))
body=box('La fecha de evaluación es explícita',table(rows,[('case','Escenario'),('assessment_date','assessment_date'),('expires_on','expires_on'),('exception_status','exception_status'),('findings','Hallazgos'),('gate','Gate')]))
body+=note('La expiración es inclusiva: expires_on = assessment_date sigue vigente. La evaluación usa 2026-10-29 del modelo, no el reloj del sistema.')
body+=box('Misma observación declarada; mismo resultado de autorización',table(rows,[('case','Escenario'),('id','Endpoint sintético'),('decision','Regla ganadora'),('profile','Perfil'),('access','Acceso')]))
body+='<div class="two">'+box('Contexto compartido',pre({k:rows[0][k] for k in ['group','method','posture','exception_owner']}))+box('Baseline explícita en ambos modelos',pre(expired['baseline']))+'</div>'
body+=box('Hallazgo literal del caso vencido',pre(expired['findings'][0]['code']+'\n'+expired['findings'][0]['message']))
body+=note('<b>Una excepción vigente no exime de la baseline.</b> Aquí standard_requires_dot1x está explícitamente en false; cero hallazgos en current-mab depende de estos supuestos. La herramienta no retira acceso.')
page('03-mab-expiration','Una excepción vence; el acceso permanece','Comparación controlada: expired-mab frente a current-mab · observación sintética legacy-device.',body,['outputs/expired-mab/audit.json','outputs/current-mab/audit.json'],'legacy-device endpoint in both audits, assessment dates, counts, gates, shared baseline and expired finding literal code/message.')

d=audits['intent-mismatch']; f=d['findings'][0]; c=next(x for x in d['checks'] if not x['passed'])
body='<div class="stats">'+stat(d['counts']['checks'],'comprobaciones de intención')+stat(d['counts']['failed_checks'],'discrepancia exacta de perfil')+stat(c['expected_profile'],'expected_profile')+stat(c['actual_profile'],'actual_profile')+'</div>'
body+=box('Comprobación que falla · '+esc(c['id']),table([c],[('group','group'),('method','method'),('posture','posture'),('decision','decision / ganadora'),('passed','passed')]))
body+=box('Evidencia literal del hallazgo INTENT_MISMATCH',pre(f['evidence']))
body+=pre((P/'outputs/intent-mismatch.log').read_text())
body+=note('Se comparan IDs exactos de perfil contra la intención declarada. La regla employees-compliant gana y entrega staff; el modelo de este escenario esperaba deny. La herramienta no modifica reglas.')
page('04-intent-mismatch','Esperado: deny. Resultado: staff.','Escenario: intent-mismatch · una diferencia concreta vinculada a su regla ganadora.',body,['outputs/intent-mismatch/audit.json','outputs/intent-mismatch.log'],'Only failed check (staff-pass); full finding evidence; exact scenario log. Counts from audit.')

body=box('Pruebas locales · salida original',pre((P/'logs/pytest.stdout.log').read_text()))
body+=box('Matriz real de la CLI',table([dict(s,states=s.get('states','—'),findings=s.get('findings','—')) for s in summary],[('case','Escenario'),('exit_code','Exit'),('states','Estados'),('findings','Hallazgos'),('artifacts','Archivos'),('status','Estado')]))
body+=note('7 paquetes × 9 archivos = 63 archivos emitidos. Se verificaron 56 hashes internos (8 por paquete; cada manifest excluye su propio hash). invalid-reference: exit 2 y ningún directorio de salida.')
body+=box('Integridad y cobertura verificadas',pre((P/'logs/examples.stdout.log').read_text().splitlines()[-1]+'\n'+f'CSV ↔ JSON: {verification["csv_json_projections_verified"]} proyecciones verificadas.\n'+f'Por escenario: Σ effective_states + estados @default = {verification["modeled_states_per_scenario"]}.\n'+'Repositorio: contenido idéntico antes y después; Git limpio.'))
body+=note('baseline: cero hallazgos bajo los supuestos declarados. Esta ejecución local no acredita CI remota ni seguridad de una red.')
page('05-verification','124 pruebas; ocho escenarios reproducibles','Python 3.12.14 · ejecución local separada · hashes y cobertura contrastados con los archivos originales.',body,['logs/pytest.stdout.log','outputs/summary.json','logs/verification.json','logs/run.json','logs/examples.stdout.log'],'Full pytest stdout; all 8 summary rows. Verification counts from assertions; literal final runner line.')
(P/'provenance/page-sources.json').write_text(json.dumps(pages,indent=2)+'\n')
print(json.dumps(verification,indent=2))
