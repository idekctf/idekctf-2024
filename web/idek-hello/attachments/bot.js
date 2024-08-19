/*
    script revamped from corctf

    this does not match the remote setup exactly, which uses the redpwn admin bot
    this is just to facilitate local testing

    npm i puppeteer
*/
let puppeteer;
const { parseArgs } = require("util");

const options = {
    CHALLENGE_ORIGIN: {
        type: "string",
        short: "c",
        default: "http://localhost:1337"
    }
};

let {
    values: { CHALLENGE_ORIGIN },
    positionals: [ TARGET_URL ]
} = parseArgs({ args: process.argv.slice(2), options, strict: false });

if (!TARGET_URL) {
    console.error(`\
Usage: node bot.js [-c CHALLENGE_ORIGIN] TARGET_URL

Arguments:
    TARGET_URL:         the url that the admin bot will visit

Options:
    CHALLENGE_ORIGIN:   the origin where the challenge instance is hosted
                        (default is http://localhost:1337)
`);
    process.exit(1);
}

// visiting logic

puppeteer = require("puppeteer");
const sleep = d => new Promise(r => setTimeout(r, d));

const visit = async () => {
    let browser;
    try {
        browser = await puppeteer.launch({
            headless: true,
            pipe: true,
            args: [
                "--no-sandbox",
                "--disable-setuid-sandbox",
                "--js-flags=--noexpose_wasm,--jitless",
            ],
            dumpio: true
        });

        const ctx = await browser.createBrowserContext();

        const page = await ctx.newPage();
        await page.goto(CHALLENGE_ORIGIN, { timeout: 3000 });
        await page.setCookie({ name: 'FLAG', value: 'idek{PLACEHOLDER}', httpOnly: true });
        await page.goto(TARGET_URL, { timeout: 3000, waitUntil: 'domcontentloaded' });
        await sleep(5000);

        await browser.close();
        browser = null;
    } catch (err) {
        console.log(err);
    } finally {
        if (browser) await browser.close();
    }
};

visit();
