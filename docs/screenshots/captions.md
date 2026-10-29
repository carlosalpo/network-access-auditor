# Captions y texto alternativo

Todos los visores están rotulados **Not product UI**. Son evidencia offline de modelos sintéticos, no capturas de Cisco ISE ni pruebas de una red real.

## 01 — Riesgos y testigo · selección de portafolio 1

Archivo: `images/01-risk-witness.jpg`

**ES:** Una regla amplia gana en los 30 estados del modelo NAC y produce 15 hallazgos. El testigo vincula unclassified con broad-first y el perfil staff; los cuatro riesgos agregados tienen estados afectados que se solapan.

**EN:** A broad first rule wins all 30 modeled NAC states and produces 15 findings. A witness links unclassified to broad-first and the staff profile; the four aggregated risks have overlapping affected states.

**Alt ES:** Visor de evidencia offline con 15 hallazgos, cuatro códigos de riesgo y testigo unclassified, dot1x, compliant, broad-first, staff, standard. Pie con límites del modelo y etiqueta Not product UI.

**Alt EN:** Offline evidence viewer showing 15 findings, four risk codes and a witness with unclassified, dot1x, compliant, broad-first, staff and standard. Model limitations and Not product UI label are visible.

## 02 — Cobertura y reglas sombreadas

Archivo: `images/02-rule-coverage.jpg`

**ES:** La cobertura conserva la primera coincidencia: broad-first gana 30 estados y sombrea cinco reglas. Otro escenario muestra unreachable-admin cubierta por admins-compliant, con su testigo concreto.

**EN:** Coverage preserves first-match semantics: broad-first wins 30 states and shadows five rules. A separate scenario shows unreachable-admin covered by admins-compliant, with a concrete witness.

**Alt ES:** Tablas de cobertura potencial, efectiva y sombreada; broad-first gana 30 estados y las cinco reglas siguientes ganan cero. Contraste de unreachable-admin y dominio de 30 estados modelados.

**Alt EN:** Tables of potential, effective and shadowed coverage; broad-first wins 30 states and the following five rules win zero. Includes unreachable-admin comparison and the 30-state modeled domain.

## 03 — Expiración MAB · selección de portafolio 2

Archivo: `images/03-mab-expiration.jpg`

**ES:** En la evaluación del 29 de octubre de 2026, la excepción que venció el día 28 genera un hallazgo; la que vence el día 29 sigue vigente. El acceso modelado permanece igual. Ambos casos declaran standard_requires_dot1x: false; una excepción vigente no exime de la baseline.

**EN:** At the October 29, 2026 assessment, the exception expiring on the 28th produces one finding; the exception expiring on the 29th remains current. Modeled access is unchanged. Both cases declare standard_requires_dot1x: false; a current exception does not waive baseline controls.

**Alt ES:** Comparación expired-mab y current-mab: fechas 28 y 29 de octubre, estados expired y current, uno y cero hallazgos. Ambos conservan legacy-managed y staff. Se muestran baseline explícita, fecha inclusiva y límites offline.

**Alt EN:** expired-mab and current-mab comparison: October 28 and 29 expiration dates, expired and current status, one and zero findings. Both retain legacy-managed and staff. Explicit baseline, inclusive date boundary and offline limitations are shown.

## 04 — Intención frente a resultado

Archivo: `images/04-intent-mismatch.jpg`

**ES:** El check staff-pass espera deny, pero la primera regla aplicable employees-compliant entrega staff. La evidencia conserva el contexto y los IDs exactos, con una discrepancia entre cinco comprobaciones.

**EN:** The staff-pass check expects deny, but the first matching employees-compliant rule returns staff. Evidence preserves the context and exact IDs, with one mismatch across five checks.

**Alt ES:** Visor de intent-mismatch con expected_profile deny, actual_profile staff, contexto employees, dot1x y compliant, y regla ganadora employees-compliant. JSON literal y log de exit 1.

**Alt EN:** intent-mismatch viewer showing expected_profile deny, actual_profile staff, employees, dot1x and compliant context, and employees-compliant as the winner. Literal JSON evidence and exit 1 log.

## 05 — Pruebas y trazabilidad

Archivo: `images/05-verification.jpg`

**ES:** Ejecución local: 124 pruebas y ocho escenarios verificados. Siete modelos aceptados generan nueve archivos cada uno; la referencia inválida devuelve exit 2 sin salida. Se comprobaron hashes, cobertura y consistencia CSV/JSON.

**EN:** Local execution: 124 tests and eight verified scenarios. Seven accepted models generate nine files each; the invalid reference returns exit 2 with no output. Hashes, coverage and CSV/JSON consistency were checked.

**Alt ES:** Salida original de 124 pruebas pasadas, tabla de ocho escenarios con exits, estados, hallazgos y archivos; verificación de 56 hashes internos y 35 proyecciones CSV/JSON. No acredita CI ni seguridad real.

**Alt EN:** Original output of 124 passing tests, eight-scenario table with exits, states, findings and files; verification of 56 internal hashes and 35 CSV/JSON projections. Does not attest remote CI or real network security.
