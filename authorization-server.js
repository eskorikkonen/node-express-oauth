const fs = require("fs")
const express = require("express")
const bodyParser = require("body-parser")
const jwt = require("jsonwebtoken")
const {
	randomString,
	containsAll,
	decodeAuthCredentials,
	timeout,
} = require("./utils")

const config = {
	port: 9001,
	privateKey: fs.readFileSync("assets/private_key.pem"),

	clientId: "my-client",
	clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
	redirectUri: "http://localhost:9000/callback",

	authorizationEndpoint: "http://localhost:9001/authorize",
}

const clients = {
	"my-client": {
		name: "Sample Client",
		clientSecret: "zETqHgl0d7ThysUqPnaFuLOmG1E=",
		scopes: ["permission:name", "permission:date_of_birth"],
	},
	"test-client": {
		name: "Test Client",
		clientSecret: "TestSecret",
		scopes: ["permission:name"],
	},
}

const users = {
	user1: "password1",
	john: "appleseed",
}

const requests = {}
const authorizationCodes = {}

let state = ""

const app = express()
app.set("view engine", "ejs")
app.set("views", "assets/authorization-server")
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/authorize', (req, res) => {
	var clientId = req.query.client_id;
	if (!clients[clientId]) {
		return res.status(401).end();
	}
	if (!containsAll(clients[clientId].scopes, req.query.scope.split(" "))) {
		return res.status(401).end();
	}

	var requestId = randomString();
	requests[requestId] = req.query;

	res.status(200).render("login", { client: clients[clientId], scope: req.query.scope, requestId });
});

app.post('/approve', (req, res) => {
	const { userName, password, requestId } = req.body;
	if (!users[userName]) {
		return res.status(401).end();
	} else if (users[userName] !== password) {
		res.status(401).end();
		return;
	} else if (!requests[requestId]) {
		return res.status(401).end();
	}

	const clientRequest = requests[requestId];
	delete requests[requestId];

	const key = randomString();
	authorizationCodes[key] = { clientReq: clientRequest, userName };

	const url = new URL(clientRequest.redirect_uri);
	url.searchParams.append('code', key);
	url.searchParams.append('state', clientRequest.state);

	res.redirect(url);
});

app.post('/token', (req, res) => {
	if (!req.headers.authorization) {
		return res.status(401).end();
	}

	const { clientId, clientSecret } = decodeAuthCredentials(req.headers.authorization);

	if (!clients[clientId] || clients[clientId].clientSecret !== clientSecret) {
		return res.status(401).end();
	}

	const { code } = req.body;

	if (!code || !authorizationCodes[code]) {
		return res.status(401).end();
	}

	const authorizationCode = authorizationCodes[code];
	delete authorizationCodes[code];

	const token = jwt.sign(
		{
			userName: authorizationCode.userName,
			scope: authorizationCode.clientReq.scope
		},
		config.privateKey,
		{ algorithm: 'RS256'}
	);

	return res.status(200).json({access_token: token, token_type: "Bearer"}).send();
});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes

module.exports = { app, requests, authorizationCodes, server }
