const express = require('express');
const crypto = require('crypto');
const cookieParser = require("cookie-parser");
const app = express();
const port = process.env.PORT || 1337;
const ADMIN_COOKIE = process.env.ADMIN_COOKIE || 'redacted_admin_cookie';

app.use(cookieParser());
app.use(express.static('static'));
app.set('view engine', 'ejs');

app.use(function (req, res, next) {
  res.setHeader(
    'Content-Security-Policy',
    `script-src 'self'; object-src 'none'; frame-src 'none'; child-src 'none';`
  );
  next();
});

const posts = require('./posts.json');

app.get('/api/post/:id', (req, res) => {
  const id = req.params.id;
  if (posts.hasOwnProperty(id)){
    if (posts[id]['hidden'] === true && req.cookies.ADMIN_COOKIE !== ADMIN_COOKIE) {
      return res.status(403).json( {'error': 'unauthorized!'} );
    };
    return res.json(posts[id]);
  } else {
    return res.status(404).json( {'error': `post ${id} does not exist`} );
  }
});

app.get('/about', (req, res) => {
  return res.render('about');
});

app.get('/posts', (req, res) => {
  return res.render('post');
});

app.use('/', (req, res) => {
  return res.render('index');
});

app.listen(port, () => {
  console.log(`App listening on port ${port}`);
});

