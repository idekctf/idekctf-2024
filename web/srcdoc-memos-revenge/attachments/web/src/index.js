const cookie = require("cookie");
const http = require("http");
const { spawn } = require("child_process");

let ips = new Map();

const escape = html => html
	.replaceAll('"', "&quot;")
	.replaceAll("<", "&lt;")
	.replaceAll(">", "&gt;");

const sleep = d => new Promise(r => setTimeout(r, d));

const handler = async (req, res) => {
	const url = new URL(req.url, "http://localhost");
	let memo, targetUrl, ip;

	switch (url.pathname) {
	case "/":
		memo =
			cookie.parse(req.headers.cookie || "").memo ??
			`surely...`;

		res.setHeader("Content-Type", "text/html; charset=utf-8");
		res.end(`
<style>
	textarea { resize: none; }
	h1 { margin-top: 80px; }
	iframe { min-width: 0; }
	input, textarea {
		font-size: 18px;
		margin-top: 30px;
	}
	body {
		display: flex;
		flex-direction: column;
		align-items: center;
		height: 100vh;
		margin: 0;
	}
	.horizontal {
		display: flex;
		height: 50%;
		width: 80%;
	}
	.horizontal > * {
		flex: 1;
		margin: 15px;
	}
</style>
<script>
document.head.insertAdjacentHTML(
	"beforeend",
	\`<meta http-equiv="Content-Security-Policy" content="script-src 'none';">\`
);
if (window.opener !== null) {
	console.error("has opener");
	document.documentElement.remove();
}
</script>

<h1>srcdoc memos revenge</h1>
<div class="horizontal">
	<iframe srcdoc="${escape(memo)}"></iframe>
	<textarea name="memo" placeholder="<b>TODO</b>: ..." form="update">${escape(memo)}</textarea>
</div>
<form id="update" action="/memo">
	<input type="submit" value="update memo">
</form>
		`.trim());
		break;

	case "/memo":
		memo = url.searchParams.get("memo") ?? "";
		res.statusCode = 302;
		res.setHeader("Set-Cookie", cookie.serialize("memo", memo));
		res.setHeader("Location", "/");
		res.end();
		break;

	case "/visit":
		ip = req.socket.remoteAddress;
		targetUrl = url.searchParams.get("url");
		res.setHeader("Content-Type", "text/plain; charset=utf-8");
		
		if (!targetUrl) {
			res.statusCode = 400;
			res.end("no url provided");
			break;
		}
		
		// you can only visit once every 10 seconds
		if (ips.has(ip) && ips.get(ip) + 10*1000 > Date.now()) {
			res.statusCode = 429;
			res.end("still visiting, try again in a bit");
			break;
		}

		ips.set(ip, Date.now());

		console.log(`Visiting ${targetUrl}`);

		const proc = spawn("node", ["bot.js", "-c", "http://localhost:1337", targetUrl], { detached: true });

		let stdoutChunks = [];
		let stderrChunks = [];

		// this part is taken from aacsp, justctf
		proc.on('exit', (code) =>
			console.log('Process exited with code', code)
		);
		
		proc.stdout.on('data', (data) => {
			stdoutChunks = stdoutChunks.concat(data);
		});
		proc.stdout.on('end', () => {
			const stdoutContent = Buffer.concat(stdoutChunks).toString();
			console.log('stdout chars:', stdoutContent.length);
			console.log(stdoutContent);
		});
	
		proc.stderr.on('data', (data) => {
			stderrChunks = stderrChunks.concat(data);
		});
		proc.stderr.on('end', () => {
			const stderrContent = Buffer.concat(stderrChunks).toString();
			console.log('stderr chars:', stderrContent.length);
			console.log(stderrContent);
		});

		await Promise.race([
			new Promise(r => proc.on("exit", r)),
			sleep(30000)
		]);
	  
		if (proc.exitCode === null) {
		  process.kill(-proc.pid);
		}

		res.end("the admin bot has visited your link");
		break;

	default:
		res.statusCode = 404;
		res.setHeader("Content-Type", "text/plain; charset=utf-8");
		res.end("not found");
	}
};

const server = http.createServer((req, res) => {
	try {
		handler(req, res);
	} catch (e) {
		console.log(e);
		res.statusCode = 500;
		res.setHeader("Content-Type", "text/plain; charset=utf-8");
		res.end("lmao");
	}
});

server.listen(1337, "0.0.0.0", () => console.log("listening"));
