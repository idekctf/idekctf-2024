const sleep = time => new Promise(resolve => setTimeout(resolve, time))

const challenges = new Map([
  ['idek-hello', {
    name: 'Hello',
    timeout: 10000,
    handler: async (url, ctx) => {
      const page = await ctx.newPage();
      await page.goto('http://idek-hello.chal.idek.team:1337/', { timeout: 3000 });
      await page.setCookie({ name: 'FLAG', value: 'idek{Ghazy_N3gm_Elbalad}', httpOnly: true });
      await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' });
      await sleep(5000);
    }
  }],
  ['srcdoc-memos', {
    name: 'srcdoc memos',
    timeout: 25000,
    handler: async (url, ctx) => {
      const FLAG = "idek{shd_reallll_y_be_srcdoc_memo_not_memos_bc_u_can_only_store_one1_memo_but_shrug}";
	
      let page = await ctx.newPage();
      await page.goto("http://srcdoc-memos.chal.idek.team:1337/", { timeout: 3000, waitUntil: 'domcontentloaded' });
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
      await page.goto(url, { timeout: 3000, waitUntil: "domcontentloaded" });
      await sleep(20000);
    },
  }],
  ["flamethrower", {
    name: "flamethrower",
    timeout: 15000,
    handler: async (url, ctx) => {
      const token = "0b8316282ad3dcd7a200e27229084e6c75a644e8c95bf725fe00054702070c81";
      
      let page = await ctx.newPage();
      await page.goto('http://flamethrower.chal.idek.team:1337/', { timeout: 3000 });
      await page.setCookie({ name: 'ADMIN_COOKIE', value: token });
      await page.goto(url, { timeout: 3000, waitUntil: 'domcontentloaded' });
      await sleep(5000);
    }
  }]
])

module.exports = {
  challenges
}