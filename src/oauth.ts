// adapted from https://hamzah.syedahmed.net/posts/oauth-pkce-client, and @badgateway/oauth2-client docs.

import {
	OAuth2Client,
	generateCodeVerifier,
	OAuth2Fetch,
} from "@badgateway/oauth2-client";
import { randomUUID } from "crypto";
import open from "open";
import { LocalStorage } from "node-localstorage";

const STORAGE_LOCATION = "./storage";
const SERVER = "https://auth.sbhs.net.au/";
const CLIENT_ID = "01hqkmmk28esk8rqyh4qka52se";
const AUTH_ENDPOINT = "https://auth.sbhs.net.au/authorize";
const TOKEN_ENDPOINT = "https://auth.sbhs.net.au/token";
const REDIRECT_URI = "https://redirectmeto.com/http://localhost:6459";
const SCOPES = ["all-ro"];
const PORT = 6459;

const localStorage = new LocalStorage(STORAGE_LOCATION);
const client = new OAuth2Client({
	server: SERVER,
	clientId: CLIENT_ID,
	authorizationEndpoint: AUTH_ENDPOINT,
	tokenEndpoint: TOKEN_ENDPOINT,
});
async function login() {
	const codeVerifier = await generateCodeVerifier();
	const state = randomUUID();
	const authorizeUri = await client.authorizationCode.getAuthorizeUri({
		redirectUri: REDIRECT_URI,
		state,
		codeVerifier,
		scope: SCOPES,
	});
	localStorage.setItem("codeVerifier", codeVerifier);
	localStorage.setItem("state", state);
	Bun.serve({
		port: PORT,
		async fetch(request) {
			const url = new URL(request.url);
			const query = Object.fromEntries(url.searchParams.entries());
			if (query.error) {
				await logout();
				throw new Error("unable to authenticate.");
			}
			if (query.code) {
				const codeVerifier = localStorage.getItem("codeVerifier");
				const state = localStorage.getItem("state");
				if (!codeVerifier || !state) {
					throw new Error("could not find codeVerifier or state.");
				}
				const token = await client.authorizationCode.getTokenFromCodeRedirect(
					request.url,
					{
						redirectUri: REDIRECT_URI,
						state,
						codeVerifier,
					},
				);
				localStorage.setItem("token", JSON.stringify(token));
			}
			return new Response("you may now return to the terminal.");
		},
	});
	open(authorizeUri);
}

async function logout() {
	localStorage.removeItem("token");
	localStorage.setItem("loggedIn", "false");
}

function getToken() {
	const tokenValue = localStorage.getItem("token");
	if (!tokenValue) {
		throw new Error("could not find tokenValue");
	}
	const token = JSON.parse(tokenValue);
	return token;
}

export const fetchWrapper = new OAuth2Fetch({
	client,

	async getNewToken() {
		await login();
		return getToken();
	},
	storeToken(token) {
		localStorage.setItem("token", JSON.stringify(token));
	},
	getStoredToken: getToken,
});
