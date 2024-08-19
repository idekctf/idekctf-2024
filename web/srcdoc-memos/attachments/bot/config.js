const SITE = process.env.SITE || "http://web:1337";

const sleep = time => new Promise(resolve => setTimeout(resolve, time))

const challenges = new Map([
  ['srcdoc-memos', {
    name: 'srcdoc memos',
    timeout: 30000,
    handler: async (url, ctx) => {
      const FLAG = "idek{REDACTED}";
    
      let page = await ctx.newPage();
      await page.goto(SITE, { timeout: 3000, waitUntil: 'domcontentloaded' });
      await page.evaluate(
          FLAG => document.querySelector('textarea[name="memo"]').value = FLAG,
          FLAG
      );
      await Promise.all([
          page.waitForNavigation({ waitUntil: 'load' }),
          page.click('input[type="submit"]')
      ]);
      await page.close();

      page = await ctx.newPage();
      await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' });
      await sleep(20000);
    }
  }]
])

module.exports = {
  challenges
}
