
'use strict';
document.documentElement.classList.add('js');
const menu=document.querySelector('.menu-button'),nav=document.querySelector('.nav');
menu.addEventListener('click',()=>{const open=menu.getAttribute('aria-expanded')!=='true';menu.setAttribute('aria-expanded',String(open));menu.textContent=open?'Close':'Menu';nav.classList.toggle('is-open',open)});
nav.addEventListener('click',e=>{if(e.target.closest('a')){menu.setAttribute('aria-expanded','false');menu.textContent='Menu';nav.classList.remove('is-open')}});
document.addEventListener('keydown',e=>{if(e.key==='Escape'&&nav.classList.contains('is-open')){menu.setAttribute('aria-expanded','false');menu.textContent='Menu';nav.classList.remove('is-open');menu.focus()}});
const tabButtons=[...document.querySelectorAll('[data-tier]')];
function selectTier(button,focus=false){tabButtons.forEach(b=>{const active=b===button;b.setAttribute('aria-selected',String(active));b.tabIndex=active?0:-1;document.getElementById(b.getAttribute('aria-controls')).hidden=!active});if(focus)button.focus()}
tabButtons.forEach((b,i)=>{b.addEventListener('click',()=>selectTier(b));b.addEventListener('keydown',e=>{let n=i;if(e.key==='ArrowRight')n=(i+1)%tabButtons.length;else if(e.key==='ArrowLeft')n=(i+tabButtons.length-1)%tabButtons.length;else if(e.key==='Home')n=0;else if(e.key==='End')n=tabButtons.length-1;else return;e.preventDefault();selectTier(tabButtons[n],true)})});
document.querySelectorAll('.copy-button').forEach(button=>button.addEventListener('click',async()=>{const value=button.parentElement.querySelector('code').textContent;let copied=false;try{if(navigator.clipboard){await navigator.clipboard.writeText(value);copied=true}}catch(_e){}if(!copied){const field=document.createElement('textarea');field.value=value;field.style.position='fixed';field.style.opacity='0';document.body.append(field);field.select();try{copied=document.execCommand('copy')}catch(_e){}field.remove();button.focus()}button.textContent=copied?'Copied':'Select the command text to copy';button.parentElement.querySelector('.live-status').textContent=copied?'Command text copied.':'';setTimeout(()=>button.textContent='Copy commands',3000)}));

if(document.getElementById('check-search')){
  const search=document.getElementById('check-search');
  const grid=document.getElementById('catalog-results');
  const count=document.getElementById('catalog-count');
  const more=document.getElementById('show-checks');
  const reset=document.getElementById('reset-filters');
  const categoryButtons=[...document.querySelectorAll('[data-category]')];
  const tierButtons=[...document.querySelectorAll('[data-tier-filter]')];
  const severityButtons = [...document.querySelectorAll('[data-severity-filter]')];
  let severity = 'All severities';
  let category='All categories',tier='All tiers',expanded=false;
  const PAGE_SIZE=12;
  function markButtons(){
    for (const button of severityButtons) {
      button.setAttribute('aria-pressed', String(button.dataset.severityFilter === severity));
    }
    categoryButtons.forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.category===category)));
    tierButtons.forEach(b=>b.setAttribute('aria-pressed',String(b.dataset.tierFilter===tier)));
  }
  function appendSeverityText(parent,text){
    const pattern=/\b(critical|warning|notice|info)\b/gi;
    let last=0;
    for(const match of text.matchAll(pattern)){
      parent.append(document.createTextNode(text.slice(last,match.index)));
      const term=document.createElement('span');
      term.className='severity-word severity-'+match[0].toLowerCase();
      term.textContent=match[0];parent.append(term);last=match.index+match[0].length;
    }
    parent.append(document.createTextNode(text.slice(last)));
  }
  function renderCatalog(){
    const query=search.value.trim().toLowerCase();
    const matches=window.DROYNIS_CHECKS.filter(c=>
      (category==='All categories'||c.category===category)&&
      (tier==='All tiers'||c.tier===tier)&&
      (severity === 'All severities' || c.severity === severity) &&
      [c.id,c.title,c.tier,c.severity,c.failsWhen,c.category].join(' ').toLowerCase().includes(query)
    );
    const visible=expanded?matches:matches.slice(0,PAGE_SIZE);
    grid.replaceChildren();
    for(const c of visible){
      const article=document.createElement('article');article.className='check-card';
      const meta=document.createElement('div');meta.className='check-meta';
      const id=document.createElement('span');id.className='check-id';id.textContent=c.id;
      const tierLabel=document.createElement('span');tierLabel.className='tier-badge tier-'+c.tier.toLowerCase();tierLabel.textContent=c.tier;
      const severityLabel=document.createElement('span');severityLabel.className='severity-badge severity-'+c.severity.toLowerCase();severityLabel.textContent=c.severity;
      meta.append(id,tierLabel,severityLabel);
      if (c.betaAdded) {
        const badge = document.createElement('span');
        badge.className = 'beta-badge';
        badge.textContent = 'Beta';
        meta.append(badge);
      }
      const title=document.createElement('h3');title.textContent=c.title;
      const description=document.createElement('p');
      const label=document.createElement('span');label.className='failure-label';label.textContent='Flags when ';
      description.append(label);appendSeverityText(description,c.failsWhen);
      article.append(meta,title,description);grid.append(article);
    }
    if(!matches.length){
      const empty=document.createElement('p');empty.className='no-results';
      empty.textContent='No checks match these filters. Clear filters or try a different phrase.';grid.append(empty);
    }
    const scope=[];
    if(category!=='All categories')scope.push(category);
    if(tier!=='All tiers')scope.push(tier+' tier');
    if (severity !== 'All severities') scope.push(severity);
    count.textContent=`Showing ${visible.length} of ${matches.length} checks${scope.length?' · '+scope.join(' · '):''}.`;
    more.hidden=matches.length<=PAGE_SIZE;
    more.textContent=expanded?'Show fewer':'Show all '+matches.length;
    more.setAttribute('aria-expanded',String(expanded));
  }
  search.addEventListener('input',()=>{expanded=false;renderCatalog()});
  categoryButtons.forEach(b=>b.addEventListener('click',()=>{
    category=b.dataset.category;expanded=false;markButtons();renderCatalog();
  }));
  tierButtons.forEach(b=>b.addEventListener('click',()=>{
    tier=b.dataset.tierFilter;expanded=false;markButtons();renderCatalog();
  }));
  for (const button of severityButtons) {
    button.addEventListener('click', () => {
      severity = button.dataset.severityFilter;
      expanded = false;
      markButtons();
      renderCatalog();
    });
  }
  reset.addEventListener('click',()=>{
    severity = 'All severities';
    search.value='';category='All categories';tier='All tiers';expanded=false;
    markButtons();renderCatalog();search.focus();
  });
  more.addEventListener('click',()=>{
    expanded=!expanded;renderCatalog();
    if(!expanded)document.querySelector('.results-header').scrollIntoView({block:'start',behavior:'auto'});
  });
  markButtons();renderCatalog();
}
const dialog=document.getElementById('screenshot-dialog');let lastScreenshotButton=null;document.querySelectorAll('[data-screenshot]').forEach(b=>b.addEventListener('click',()=>{lastScreenshotButton=b;dialog.querySelector('img').src=b.dataset.screenshot;dialog.querySelector('img').alt=b.dataset.alt;dialog.querySelector('.dialog-title').textContent=b.dataset.title;dialog.showModal()}));dialog.querySelector('.close-dialog').addEventListener('click',()=>dialog.close());dialog.addEventListener('click',e=>{if(e.target===dialog){const r=dialog.getBoundingClientRect();if(e.clientX<r.left||e.clientX>r.right||e.clientY<r.top||e.clientY>r.bottom)dialog.close()}});dialog.addEventListener('close',()=>lastScreenshotButton?.focus());

/* Cycle the owl's rim while this page is visible. */
(() => {
  const icon = document.getElementById('site-favicon');
  const reducedMotion = window.matchMedia('(prefers-reduced-motion: reduce)');
  const colors = ['teal', 'orchid', 'amber'];
  let index = 0;
  let timer;
  function updateCycle() {
    window.clearInterval(timer);
    if (reducedMotion.matches) {
      index = 0;
      icon.href = 'assets/favicon-teal.png';
    } else if (!document.hidden) {
      timer = window.setInterval(() => {
        index = (index + 1) % colors.length;
        icon.href = 'assets/favicon-' + colors[index] + '.png';
      }, 5000);
    }
  }
  reducedMotion.addEventListener('change', updateCycle);
  document.addEventListener('visibilitychange', updateCycle);
  updateCycle();
})();

const revealEmail = document.getElementById('reveal-email');
if (revealEmail) {
  revealEmail.hidden = false;
  revealEmail.addEventListener('click', () => {
    const address = atob(revealEmail.dataset.contact);
    const link = document.createElement('a');
    link.className = 'text-link';
    link.href = 'mailto:' + address;
    link.textContent = address;
    revealEmail.replaceWith(link);
    link.focus();
  }, { once: true });
}
