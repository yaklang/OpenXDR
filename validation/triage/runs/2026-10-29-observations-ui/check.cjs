const {chromium}=require('/tmp/pwtest/node_modules/playwright');
const fs=require('fs/promises');
const path=require('path');
(async()=>{
 const browser=await chromium.launch({headless:true,executablePath:'/home/Kei/.cache/ms-playwright/chromium-1248/chrome-linux64/chrome',args:['--no-sandbox']});
 const results=[];
 try {
 for(const width of [390,1440]) for(const mode of ['many','legacy','pending','error']) {
  const page=await browser.newPage({viewport:{width,height:900}});
  const errors=[];page.on('pageerror',e=>errors.push(e.message));
  await page.route('**/*',async route=>{
   const url=new URL(route.request().url());
   if(url.origin!=='http://triage.test')return route.abort();
   const rel=url.pathname==='/'?'.triage-acceptance/index.html':url.pathname.slice(1);
   try {const body=await fs.readFile(path.join('/tmp/openxdr-observations-ui/dist',rel));await route.fulfill({body,contentType:rel.endsWith('.js')?'application/javascript':rel.endsWith('.css')?'text/css':'text/html'});}catch{await route.fulfill({status:404,body:'not found'});}
  });
  await page.goto(`http://triage.test/?case=${mode}`);
  await page.waitForSelector('.ant-card');
  const metrics=await page.evaluate(()=>{
   const summary=[...document.querySelectorAll('.ant-typography')].find(x=>x.textContent.startsWith('测试摘要：'));
   return {scrollWidth:document.documentElement.scrollWidth,viewport:innerWidth,summaryTop:summary?.getBoundingClientRect().top,excerptItems:document.querySelectorAll('section[aria-label] li').length};
  });
  if(errors.length || metrics.scrollWidth > width) throw new Error(JSON.stringify({width,mode,errors,...metrics}));
  if(process.argv[2] === 'interactive' && mode === 'many') {
   const items=page.locator('section[aria-label] li:visible');
   if(await items.count() !== 3 || metrics.summaryTop >= 900) throw new Error('Default excerpts obscure summary');
   const more=page.getByText('展开其余 27 条证据摘录',{exact:true});
   await more.click();
   if(await items.count() !== 30) throw new Error('Missing expanded excerpts');
   await page.waitForTimeout(250);
   const expand=page.getByText('展开全文',{exact:true}).first();
   if(await expand.isVisible()) {
    await expand.click();
    if(!await page.getByText('收起全文',{exact:true}).first().isVisible()) throw new Error('Missing collapse control');
    await page.getByText('收起全文',{exact:true}).first().click();
    metrics.longText='expand-collapse';
   } else {
    const full=await page.locator('section .ant-typography').allTextContents();
    if(!full.some(s=>s.includes('long-id-'.repeat(50)) && s.endsWith('操作授权。'))) throw new Error('Long text lost without expand control');
    metrics.longText='fully-visible';
   }
   await more.click();
   if(await items.count() !== 3) throw new Error('Collapse did not restore compact list');
   metrics.expandCollapsePassed=true;
  }
  results.push({width,mode,errors,...metrics});
  if(mode==='many')await page.screenshot({path:`/tmp/openxdr-observations-ui/${process.argv[2]||'before'}-${width}.png`,fullPage:true});
  await page.close();
 }
 await fs.writeFile(`/tmp/openxdr-observations-ui/${process.argv[2]||'before'}.json`,JSON.stringify(results,null,2));
 console.log(JSON.stringify(results));
 }finally{await browser.close()}
})().catch(e=>{console.error(e);process.exit(1)});
