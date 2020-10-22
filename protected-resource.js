const express = require("express")
const bodyParser = require("body-parser")
const fs = require("fs")
const jwt = require("jsonwebtoken");
const { timeout } = require("./utils")

const config = {
	port: 9002,
	publicKey: fs.readFileSync("assets/public_key.pem"),
}

const users = {
	user1: {
		username: "user1",
		name: "User 1",
		date_of_birth: "7th October 1990",
		weight: 57,
	},
	john: {
		username: "john",
		name: "John Appleseed",
		date_of_birth: "12th September 1998",
		weight: 87,
	},
}

const app = express()
app.use(timeout)
app.use(bodyParser.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/user-info', (req, res) => {
	if (!req.headers.authorization) {
		return res.status(401).end();
	}

	try {
		const token = jwt.verify(req.headers.authorization.slice("bearer ".length), config.publicKey, { algorithms: "RS256"});

		const scopes = token.scope.split(" ");
		const responseObject = {};

		scopes.forEach(scope => {
			const fieldName = scope.slice("permission:".length);
			responseObject[fieldName] = users[token.userName][fieldName];
		});

		return res.status(200).json(responseObject).send();
	} catch (error) {
		return res.status(401).end();
	}

});

const server = app.listen(config.port, "localhost", function () {
	var host = server.address().address
	var port = server.address().port
})

// for testing purposes
module.exports = {
	app,
	server,
}
