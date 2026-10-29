// CUA recipe; execute through cua_repl, not as a standalone Node browser driver.
// First invocation only:
// let browser = await cua.getBrowser({id: 'iab'});
// Read the returned API documentation before continuing.
// In later invocations, choose a NEW capture output directory and set captureRoot.
// The originals used the browser's default 1280x720 viewport, without override.
// No clip, resampling, format conversion, compositing or postprocessing.
// For each page, inspect getAXState() and the emitted image before proceeding.
let captureRoot = '/path/to/a/new/capture-directory';
let fs = await import('node:fs/promises');
let names = ['01-risk-witness','02-rule-coverage','03-mab-expiration',
             '04-intent-mismatch','05-verification'];
let tab = await cua.createBrowserTab('iab',
  'http://127.0.0.1:8769/viewer/01-risk-witness.html', {visible:false});
// Execute individually for each name, reviewing each image:
// await tab.goto('http://127.0.0.1:8769/viewer/' + name + '.html');
// await tab.getAXState();
// let bytes = await tab.screenshot({fullPage:true});
// await fs.writeFile(captureRoot + '/' + name + '.jpg', bytes, {flag:'wx'});
// await nodeRepl.emitImage(bytes);
