const cookie = require("cookie");
const http = require("http");

const escape = html => html
	.replaceAll('"', "&quot;")
	.replaceAll("<", "&lt;")
	.replaceAll(">", "&gt;");

const handler = (req, res) => {
	const url = new URL(req.url, "http://localhost");
	let memo;

	switch (url.pathname) {
	case "/":
		memo =
			cookie.parse(req.headers.cookie || "").memo ??
			`<h2>Welcome to srcdoc memos!</h2>\n<p>HTML is supported</p>`;

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

<h1>srcdoc memos</h1>
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
