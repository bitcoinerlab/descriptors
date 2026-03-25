'use strict';

// TypeDoc generates the real Output API page under the internal module tree.
// This post-process step makes docs navigation friendlier by:
// - creating a public-looking Output class alias page,
// - rewriting generated links to point to that alias,
// - injecting Output as a top-level item in the left nav,
// - adding a Classes/Output section to the landing page, and
// - hiding the landing-page "On This Page" panel so the custom section fits.

const fs = require('fs');
const path = require('path');

function getOutputFileName(outDir) {
  const classesDir = path.join(outDir, 'classes');
  if (!fs.existsSync(classesDir))
    throw new Error(`Missing classes directory in ${outDir}`);
  const classFiles = fs
    .readdirSync(classesDir)
    .filter(name => name.endsWith('Output.html'));
  const outputFile = classFiles.find(name => name === '_Internal_.Output.html') ?? classFiles[0];
  if (!outputFile) throw new Error(`Could not find Output class page in ${classesDir}`);
  return outputFile;
}

function walk(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const filePath = path.join(dir, entry.name);
    return entry.isDirectory() ? walk(filePath) : [filePath];
  });
}

function ensureOutputAlias(outDir) {
  const classesDir = path.join(outDir, 'classes');
  const outputFile = getOutputFileName(outDir);
  if (outputFile === 'Output.html') return 'Output.html';

  const sourcePath = path.join(classesDir, outputFile);
  const aliasPath = path.join(classesDir, 'Output.html');
  let html = fs.readFileSync(sourcePath, 'utf8');

  html = html.replace(
    /<ul class="tsd-breadcrumb" aria-label="Breadcrumb"><li><a href="\.\.\/modules\/_Internal_\.html">_Internal_<\/a><\/li><li><a href="" aria-current="page">Output<\/a><\/li><\/ul>/,
    '<ul class="tsd-breadcrumb" aria-label="Breadcrumb"><li><a href="" aria-current="page">Output</a></li></ul>'
  );
  html = html.replaceAll(outputFile, 'Output.html');

  fs.writeFileSync(aliasPath, html);
  return 'Output.html';
}

function replaceOutputLinks(outDir, outputFileName) {
  for (const filePath of walk(outDir)) {
    if (!/\.(html|js)$/.test(filePath)) continue;
    let content = fs.readFileSync(filePath, 'utf8');
    content = content.replaceAll(outputFileName, 'Output.html');
    fs.writeFileSync(filePath, content);
  }
}

function injectOutputNavPatch(pagePath, outDir) {
  const outputHref = path.relative(path.dirname(pagePath), path.join(outDir, 'classes', 'Output.html')).replaceAll(path.sep, '/');
  const current = path.basename(pagePath) === 'Output.html' ? ' current' : '';
  const marker = 'data-output-nav-patch';
  let html = fs.readFileSync(pagePath, 'utf8');
  if (html.includes(marker)) return;

  const classIcon = '<svg class="tsd-kind-icon" viewBox="0 0 24 24" aria-label="Class"><rect fill="var(--color-icon-background)" stroke="var(--color-ts-class)" stroke-width="1.5" x="1" y="1" width="22" height="22" rx="6"></rect><text fill="var(--color-icon-text)" x="50%" y="50%" dy="0.35em" text-anchor="middle">C</text></svg>';
  const script = `<script ${marker}>(function(){function patch(){const c=document.getElementById('tsd-nav-container');if(!c)return;for(const a of [...c.querySelectorAll('a')]){const href=a.getAttribute('href')||'';if((href.endsWith('classes/Output.html')||href.endsWith('classes/_Internal_.Output.html'))&&!a.classList.contains('tsd-output-root-link')){const li=a.closest('li');if(li)li.remove();}}if(!c.querySelector('a.tsd-output-root-link')){const li=document.createElement('li');li.innerHTML='<a href="${outputHref}" class="tsd-output-root-link${current}">${classIcon}<span>Output</span></a>';c.insertBefore(li,c.firstChild);}}function start(){const c=document.getElementById('tsd-nav-container');if(!c)return;patch();const o=new MutationObserver(patch);o.observe(c,{childList:true,subtree:true});setTimeout(()=>o.disconnect(),4000);}if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',start,{once:true});else start();})();</script>`;
  html = html.replace('</body>', `${script}</body>`);
  fs.writeFileSync(pagePath, html);
}

function patchLandingPage(outDir) {
  const candidates = ['modules.html', 'index.html']
    .map(name => path.join(outDir, name))
    .filter(filePath => fs.existsSync(filePath));

  if (candidates.length === 0)
    throw new Error(`Could not find landing page in ${outDir}`);

  const pagePath = candidates[0];
  const outputHref = path.relative(path.dirname(pagePath), path.join(outDir, 'classes', 'Output.html')).replaceAll(path.sep, '/');
  const iconBase = path.relative(path.dirname(pagePath), path.join(outDir, 'assets', 'icons.svg')).replaceAll(path.sep, '/');

  let html = fs.readFileSync(pagePath, 'utf8');
  const landingStyleMarker = 'data-output-landing-style';
  const landingStyle = `<style ${landingStyleMarker}>.page-menu{display:none}@media (min-width: 1200px){.container-main{grid-template-columns:minmax(0,1fr) minmax(0,2.5fr)!important;grid-template-areas:"sidebar content"!important}}</style>`;
  if (!html.includes(landingStyleMarker)) html = html.replace('</head>', `${landingStyle}</head>`);

  const outputSection = `<details class="tsd-panel-group tsd-member-group tsd-accordion" open><summary class="tsd-accordion-summary" data-key="section-Classes"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" aria-hidden="true"><use href="${iconBase}#icon-chevronDown"></use></svg><h2>Classes</h2></summary><dl class="tsd-member-summaries"><dt class="tsd-member-summary" id="output"><span class="tsd-member-summary-name"><svg class="tsd-kind-icon" viewBox="0 0 24 24" aria-label="Class"><use href="${iconBase}#icon-128"></use></svg><a href="${outputHref}">Output</a><a href="#output" aria-label="Permalink" class="tsd-anchor-icon"><svg viewBox="0 0 24 24" aria-hidden="true"><use href="${iconBase}#icon-anchor"></use></svg></a></span></dt><dd class="tsd-member-summary"><div class="tsd-comment tsd-typography"><p><code>Output</code> is the central class of this library.</p><p>In <code>@bitcoinerlab/descriptors</code> and <code>@bitcoinerlab/descriptors-scure</code>, it is available directly from the package. In <code>@bitcoinerlab/descriptors-core</code>, you obtain it from <code>DescriptorsFactory(...)</code>.</p></div></dd></dl></details>`;

  const modulesMarker = '<details class="tsd-panel-group tsd-member-group tsd-accordion" open><summary class="tsd-accordion-summary" data-key="section-Modules">';
  if (html.includes(outputSection)) return;
  if (!html.includes(modulesMarker))
    throw new Error(`Could not find Modules section in ${pagePath}`);
  html = html.replace(modulesMarker, `${outputSection}${modulesMarker}`);

  fs.writeFileSync(pagePath, html);
}

for (const outDirArg of process.argv.slice(2)) {
  const outDir = path.resolve(outDirArg);
  const outputFileName = getOutputFileName(outDir);
  ensureOutputAlias(outDir);
  replaceOutputLinks(outDir, outputFileName);
  patchLandingPage(outDir);
  for (const filePath of walk(outDir))
    if (filePath.endsWith('.html')) injectOutputNavPatch(filePath, outDir);
}
