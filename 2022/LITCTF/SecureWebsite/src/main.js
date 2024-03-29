require("dotenv").config();

const express = require('express');
const bodyParser = require('body-parser');
const app = express();
const ejs = require("ejs");
const {checkPassword} = require("./passwordChecker.js");

var flag = (process.env.FLAG ?? "ctf{flag}");
// I like alphanumeric passwords
var password = (process.env.password ?? "password");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

app.set('view engine', 'ejs');

app.get('/', (req, res) => {
	res.render("index");
});

app.get('/verify', (req, res) => {
	var pass = req.query.password;
	var start = performance.now();
	
	if(pass == undefined || typeof(pass) !== 'string' || !checkPassword(password,pass)) {
		res.writeHead(302, {'Location': 'about:blank'});
		var now = performance.now();
		// console.log(now - start);
		res.end();
		return;
	}
	res.render("secret",{flag: flag});
});

app.listen(8080, () => {
	console.log("STEPHANIE OTZ OTZ OTZ OTZ!!!");
});