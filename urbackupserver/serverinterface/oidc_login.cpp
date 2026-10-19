/*************************************************************************
*    UrBackup - Client/Server backup system
*    Copyright (C) 2011-2016 Martin Raiber
*
*    This program is free software: you can redistribute it and/or modify
*    it under the terms of the GNU Affero General Public License as published by
*    the Free Software Foundation, either version 3 of the License, or
*    (at your option) any later version.
*
*    This program is distributed in the hope that it will be useful,
*    but WITHOUT ANY WARRANTY; without even the implied warranty of
*    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*    GNU Affero General Public License for more details.
*
*    You should have received a copy of the GNU Affero General Public License
*    along with this program.  If not, see <http://www.gnu.org/licenses/>.
**************************************************************************/

#ifndef CLIENT_ONLY

// OpenID Connect (Keycloak) login: authorization code flow with PKCE (S256).
//
// Configured through environment variables so that the client secret never
// ends up in the database, the web UI bundle or the source tree:
//   URBACKUP_OIDC_ISSUER         e.g. https://keycloak.example.com/realms/myrealm
//   URBACKUP_OIDC_CLIENT_ID
//   URBACKUP_OIDC_CLIENT_SECRET
//   URBACKUP_OIDC_SCOPES         optional, default "openid profile email"
//
// Web UI protocol (POST to ?a=oidc_login):
//   step=config                           -> { oidc_enabled }
//   step=start&redirect_uri=...           -> { url }  (browser is sent to url)
//   step=callback&code=...&state=...      -> same result as a normal login
//
// The code is exchanged and the user identified server side (token endpoint,
// then userinfo endpoint with the access token, both over TLS to the issuer).
// SSO users are stored as "sso:<preferred_username>" in si_users with an
// unguessable password and no rights; an admin grants rights in the user
// settings. They can never collide with, or log in as, a local user.

#include "action_header.h"
#include "login.h"
#include "../../urlplugin/IUrlFactory.h"
#include "../../cryptoplugin/ICryptoFactory.h"
#include "../../Interface/Mutex.h"

#include <stdlib.h>
#include <map>

extern IUrlFactory *url_fak;
extern ICryptoFactory *crypto_fak;

namespace
{
	const char* SSO_PREFIX = "sso:";
	const int64 PENDING_TIMEOUT_MS = 10 * 60 * 1000;
	const size_t MAX_PENDING = 1000;

	struct SOidcConfig
	{
		std::string issuer;
		std::string client_id;
		std::string client_secret;
		std::string scopes;
	};

	struct SOidcPending
	{
		std::string code_verifier;
		std::string redirect_uri;
		int64 expires;
	};

	struct SOidcEndpoints
	{
		std::string authorization;
		std::string token;
		std::string userinfo;
		std::string end_session;
	};

	IMutex* getMutex()
	{
		static IMutex* mutex = Server->createMutex();
		return mutex;
	}

	std::map<std::string, SOidcPending>& getPending()
	{
		static std::map<std::string, SOidcPending> pending;
		return pending;
	}

	SOidcEndpoints& getCachedEndpoints()
	{
		static SOidcEndpoints endpoints;
		return endpoints;
	}

	std::string getEnv(const char* name)
	{
		const char* val = getenv(name);
		return val ? std::string(val) : std::string();
	}

	bool loadConfig(SOidcConfig& cfg)
	{
		cfg.issuer = getEnv("URBACKUP_OIDC_ISSUER");
		cfg.client_id = getEnv("URBACKUP_OIDC_CLIENT_ID");
		cfg.client_secret = getEnv("URBACKUP_OIDC_CLIENT_SECRET");
		cfg.scopes = getEnv("URBACKUP_OIDC_SCOPES");

		if (cfg.scopes.empty())
		{
			cfg.scopes = "openid profile email";
		}

		while (!cfg.issuer.empty() && cfg.issuer[cfg.issuer.size() - 1] == '/')
		{
			cfg.issuer.erase(cfg.issuer.size() - 1);
		}

		return !cfg.issuer.empty() && !cfg.client_id.empty() && !cfg.client_secret.empty()
			&& url_fak != NULL && crypto_fak != NULL;
	}

	void appendUtf8(std::string& out, unsigned int cp)
	{
		if (cp < 0x80)
		{
			out += static_cast<char>(cp);
		}
		else if (cp < 0x800)
		{
			out += static_cast<char>(0xC0 | (cp >> 6));
			out += static_cast<char>(0x80 | (cp & 0x3F));
		}
		else if (cp < 0x10000)
		{
			out += static_cast<char>(0xE0 | (cp >> 12));
			out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
			out += static_cast<char>(0x80 | (cp & 0x3F));
		}
		else
		{
			out += static_cast<char>(0xF0 | (cp >> 18));
			out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
			out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
			out += static_cast<char>(0x80 | (cp & 0x3F));
		}
	}

	bool parseHex4(const std::string& s, size_t pos, unsigned int& val)
	{
		if (pos + 4 > s.size())
			return false;

		val = 0;
		for (size_t i = 0; i < 4; ++i)
		{
			char c = s[pos + i];
			val <<= 4;
			if (c >= '0' && c <= '9') val |= c - '0';
			else if (c >= 'a' && c <= 'f') val |= c - 'a' + 10;
			else if (c >= 'A' && c <= 'F') val |= c - 'A' + 10;
			else return false;
		}
		return true;
	}

	void skipWs(const std::string& s, size_t& pos)
	{
		while (pos < s.size() && (s[pos] == ' ' || s[pos] == '\t' || s[pos] == '\r' || s[pos] == '\n'))
			++pos;
	}

	// pos is at the opening quote. On success pos is after the closing quote.
	bool parseJsonString(const std::string& s, size_t& pos, std::string& out)
	{
		out.clear();
		if (pos >= s.size() || s[pos] != '"')
			return false;
		++pos;

		while (pos < s.size())
		{
			char c = s[pos++];
			if (c == '"')
				return true;

			if (c != '\\')
			{
				out += c;
				continue;
			}

			if (pos >= s.size())
				return false;

			char e = s[pos++];
			switch (e)
			{
			case '"': out += '"'; break;
			case '\\': out += '\\'; break;
			case '/': out += '/'; break;
			case 'b': out += '\b'; break;
			case 'f': out += '\f'; break;
			case 'n': out += '\n'; break;
			case 'r': out += '\r'; break;
			case 't': out += '\t'; break;
			case 'u':
			{
				unsigned int cp;
				if (!parseHex4(s, pos, cp))
					return false;
				pos += 4;

				if (cp >= 0xD800 && cp < 0xDC00)
				{
					unsigned int low;
					if (pos + 6 <= s.size() && s[pos] == '\\' && s[pos + 1] == 'u'
						&& parseHex4(s, pos + 2, low) && low >= 0xDC00 && low < 0xE000)
					{
						pos += 6;
						cp = 0x10000 + ((cp - 0xD800) << 10) + (low - 0xDC00);
					}
					else
					{
						return false;
					}
				}
				appendUtf8(out, cp);
				break;
			}
			default:
				return false;
			}
		}

		return false;
	}

	// Skips one JSON value of any type (nested objects/arrays included).
	bool skipJsonValue(const std::string& s, size_t& pos)
	{
		skipWs(s, pos);
		if (pos >= s.size())
			return false;

		if (s[pos] == '"')
		{
			std::string tmp;
			return parseJsonString(s, pos, tmp);
		}

		if (s[pos] == '{' || s[pos] == '[')
		{
			size_t depth = 0;
			while (pos < s.size())
			{
				char c = s[pos];
				if (c == '"')
				{
					std::string tmp;
					if (!parseJsonString(s, pos, tmp))
						return false;
					continue;
				}
				if (c == '{' || c == '[') ++depth;
				if (c == '}' || c == ']') --depth;
				++pos;
				if (depth == 0)
					return true;
			}
			return false;
		}

		// number, true, false, null
		while (pos < s.size() && s[pos] != ',' && s[pos] != '}' && s[pos] != ']'
			&& s[pos] != ' ' && s[pos] != '\t' && s[pos] != '\r' && s[pos] != '\n')
			++pos;
		return true;
	}

	// Returns the string value of a top-level member of a JSON object.
	bool jsonGetString(const std::string& json, const std::string& key, std::string& out)
	{
		size_t pos = 0;
		skipWs(json, pos);
		if (pos >= json.size() || json[pos] != '{')
			return false;
		++pos;

		while (true)
		{
			skipWs(json, pos);
			if (pos >= json.size() || json[pos] == '}')
				return false;

			std::string name;
			if (!parseJsonString(json, pos, name))
				return false;

			skipWs(json, pos);
			if (pos >= json.size() || json[pos] != ':')
				return false;
			++pos;
			skipWs(json, pos);

			if (name == key)
			{
				return parseJsonString(json, pos, out);
			}

			if (!skipJsonValue(json, pos))
				return false;

			skipWs(json, pos);
			if (pos < json.size() && json[pos] == ',')
				++pos;
		}
	}

	std::string base64UrlEncode(const std::string& data)
	{
		std::string ret = base64_encode(reinterpret_cast<const unsigned char*>(data.data()),
			static_cast<unsigned int>(data.size()));

		std::string out;
		for (size_t i = 0; i < ret.size(); ++i)
		{
			if (ret[i] == '+') out += '-';
			else if (ret[i] == '/') out += '_';
			else if (ret[i] != '=') out += ret[i];
		}
		return out;
	}

	std::string formEncode(const std::string& s)
	{
		static const char* hex = "0123456789ABCDEF";
		std::string out;
		for (size_t i = 0; i < s.size(); ++i)
		{
			unsigned char c = static_cast<unsigned char>(s[i]);
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
				|| c == '-' || c == '_' || c == '.' || c == '~')
			{
				out += static_cast<char>(c);
			}
			else
			{
				out += '%';
				out += hex[c >> 4];
				out += hex[c & 0xF];
			}
		}
		return out;
	}

	bool getEndpoints(const SOidcConfig& cfg, SOidcEndpoints& endpoints, std::string& errmsg)
	{
		{
			IScopedLock lock(getMutex());
			if (!getCachedEndpoints().token.empty())
			{
				endpoints = getCachedEndpoints();
				return true;
			}
		}

		str_map params;
		params["timeout"] = "15";
		std::string ret;
		long http_code;
		if (!url_fak->requestUrl(cfg.issuer + "/.well-known/openid-configuration", params, ret, http_code, &errmsg))
		{
			return false;
		}

		SOidcEndpoints found;
		std::string discovered_issuer;
		jsonGetString(ret, "end_session_endpoint", found.end_session);
		if (!jsonGetString(ret, "authorization_endpoint", found.authorization)
			|| !jsonGetString(ret, "token_endpoint", found.token)
			|| !jsonGetString(ret, "userinfo_endpoint", found.userinfo)
			|| !jsonGetString(ret, "issuer", discovered_issuer)
			|| discovered_issuer != cfg.issuer)
		{
			errmsg = "Invalid OpenID Connect discovery document";
			return false;
		}

		IScopedLock lock(getMutex());
		getCachedEndpoints() = found;
		endpoints = found;
		return true;
	}

	void prunePending(int64 now)
	{
		std::map<std::string, SOidcPending>& pending = getPending();
		for (std::map<std::string, SOidcPending>::iterator it = pending.begin(); it != pending.end();)
		{
			if (it->second.expires < now)
				pending.erase(it++);
			else
				++it;
		}
	}

	bool isValidRedirectUri(const std::string& uri)
	{
		return (next(uri, 0, "http://") || next(uri, 0, "https://"))
			&& uri.find('#') == std::string::npos
			&& uri.size() < 1024;
	}

	// Finds or creates the si_users row for the SSO user, returns its id (or -1).
	int getOrCreateUser(IDatabase* db, const std::string& username, bool& admin_exists)
	{
		IQuery* q = db->Prepare("SELECT id FROM settings_db.si_users WHERE name=?");
		q->Bind(username);
		db_results res = q->Read();
		q->Reset();

		if (!res.empty())
		{
			return watoi(res[0]["id"]);
		}

		// Do not create the first user: that would disable the anonymous
		// admin login and lock everybody out, as SSO users start without rights.
		db_results any = db->Read("SELECT id FROM settings_db.si_users WHERE name NOT LIKE 'sso:%' LIMIT 1");
		admin_exists = !any.empty();
		if (!admin_exists)
		{
			return -1;
		}

		// Unguessable password: login with a password is impossible for SSO users
		std::string salt = Server->secureRandomString(32);
		size_t pbkdf2_rounds = 10000;
		std::string pw = strlower(crypto_fak->generatePasswordHash(
			hexToBytes(Server->GenerateHexMD5(Server->secureRandomString(64))), salt, pbkdf2_rounds));

		q = db->Prepare("INSERT INTO settings_db.si_users (name, password_md5, salt, pbkdf2_rounds) VALUES (?,?,?,?)");
		q->Bind(username);
		q->Bind(pw);
		q->Bind(salt);
		q->Bind(pbkdf2_rounds);
		q->Write();
		q->Reset();

		return static_cast<int>(db->getLastInsertID());
	}
}

ACTION_IMPL(oidc_login)
{
	JSON::Object ret;
	ret.set("api_version", 2);

	Helper helper(tid, &POST, &PARAMS);
	std::string step = POST["step"];

	SOidcConfig cfg;
	bool enabled = loadConfig(cfg);

	if (step == "config")
	{
		ret.set("success", true);
		ret.set("oidc_enabled", enabled);
		helper.Write(ret.stringify(false));
		return;
	}

	if (step == "session")
	{
		// Session validity check that, unlike the settings/status actions,
		// also works for users that have no rights (yet).
		SUser* s = helper.getSession();
		bool valid = false;
		if (s != NULL)
		{
			str_map::iterator it = s->mStr.find("login");
			valid = it != s->mStr.end() && it->second == "ok";
		}
		ret.set("success", valid);
		if (valid)
		{
			ret.set("username", s->mStr["username"]);
		}
		helper.Write(ret.stringify(false));
		return;
	}

	if (step == "logout")
	{
		// Works for every session: drops the UrBackup session and, for an SSO
		// session, returns the URL that ends the Keycloak session as well.
		std::string id_token;
		SUser* logout_session = helper.getSession();
		if (logout_session != NULL)
		{
			str_map::iterator it = logout_session->mStr.find("oidc_id_token");
			if (it != logout_session->mStr.end())
			{
				id_token = it->second;
			}
		}

		std::string ses = POST["ses"];
		helper.releaseAll();
		if (!ses.empty())
		{
			Server->getSessionMgr()->RemoveSession(ses);
		}

		ret.set("success", true);

		// End the Keycloak session from the server (back channel) so that the
		// browser stays in this application and never visits the identity
		// provider's logout pages.
		SOidcEndpoints logout_endpoints;
		std::string logout_err;
		if (enabled && !id_token.empty() && getEndpoints(cfg, logout_endpoints, logout_err))
		{
			std::string end_session = logout_endpoints.end_session.empty()
				? cfg.issuer + "/protocol/openid-connect/logout" : logout_endpoints.end_session;
			std::string sep = end_session.find('?') == std::string::npos ? "?" : "&";

			str_map logout_params;
			logout_params["timeout"] = "10";
			std::string logout_ret;
			long logout_code;
			if (!url_fak->requestUrl(end_session + sep
				+ "id_token_hint=" + formEncode(id_token)
				+ "&client_id=" + formEncode(cfg.client_id),
				logout_params, logout_ret, logout_code, &logout_err))
			{
				Server->Log("OIDC logout at the provider did not complete", LL_WARNING);
			}
		}

		helper.Write(ret.stringify(false));
		return;
	}

	if (!enabled)
	{
		ret.set("success", false);
		ret.set("oidc_error", std::string("SSO is not configured"));
		helper.Write(ret.stringify(false));
		return;
	}

	std::string errmsg;
	SOidcEndpoints endpoints;
	if (!getEndpoints(cfg, endpoints, errmsg))
	{
		Server->Log("OIDC discovery failed: " + errmsg, LL_ERROR);
		ret.set("success", false);
		ret.set("oidc_error", std::string("Could not reach the SSO provider"));
		helper.Write(ret.stringify(false));
		return;
	}

	if (step == "start")
	{
		std::string redirect_uri = POST["redirect_uri"];
		if (!isValidRedirectUri(redirect_uri))
		{
			ret.set("success", false);
			ret.set("oidc_error", std::string("Invalid redirect uri"));
			helper.Write(ret.stringify(false));
			return;
		}

		std::string state = Server->secureRandomString(40);
		SOidcPending pending;
		pending.code_verifier = Server->secureRandomString(64);
		pending.redirect_uri = redirect_uri;
		int64 now = Server->getTimeMS();
		pending.expires = now + PENDING_TIMEOUT_MS;

		{
			IScopedLock lock(getMutex());
			prunePending(now);
			if (getPending().size() >= MAX_PENDING)
			{
				ret.set("success", false);
				ret.set("oidc_error", std::string("Too many pending logins"));
				helper.Write(ret.stringify(false));
				return;
			}
			getPending()[state] = pending;
		}

		std::string challenge = base64UrlEncode(crypto_fak->sha256Binary(pending.code_verifier));

		std::string sep = endpoints.authorization.find('?') == std::string::npos ? "?" : "&";
		std::string url = endpoints.authorization + sep
			+ "response_type=code"
			+ "&client_id=" + formEncode(cfg.client_id)
			+ "&redirect_uri=" + formEncode(redirect_uri)
			+ "&scope=" + formEncode(cfg.scopes)
			+ "&state=" + state
			+ "&code_challenge=" + challenge
			+ "&code_challenge_method=S256";

		ret.set("success", true);
		ret.set("url", url);
		helper.Write(ret.stringify(false));
		return;
	}

	if (step != "callback")
	{
		ret.set("success", false);
		ret.set("oidc_error", std::string("Unknown step"));
		helper.Write(ret.stringify(false));
		return;
	}

	// Callback: state is single use
	SOidcPending pending;
	{
		IScopedLock lock(getMutex());
		std::map<std::string, SOidcPending>::iterator it = getPending().find(POST["state"]);
		if (it == getPending().end() || it->second.expires < Server->getTimeMS())
		{
			ret.set("success", false);
			ret.set("oidc_error", std::string("Login expired, please try again"));
			helper.Write(ret.stringify(false));
			return;
		}
		pending = it->second;
		getPending().erase(it);
	}

	if (POST["code"].empty())
	{
		ret.set("success", false);
		ret.set("oidc_error", std::string("No authorization code received"));
		helper.Write(ret.stringify(false));
		return;
	}

	str_map params;
	params["method"] = "post";
	params["timeout"] = "20";
	params["postdata"] = "grant_type=authorization_code"
		"&code=" + formEncode(POST["code"])
		+ "&redirect_uri=" + formEncode(pending.redirect_uri)
		+ "&client_id=" + formEncode(cfg.client_id)
		+ "&client_secret=" + formEncode(cfg.client_secret)
		+ "&code_verifier=" + formEncode(pending.code_verifier);
	params["content_type"] = "application/x-www-form-urlencoded";

	std::string token_response;
	long http_code;
	if (!url_fak->requestUrl(endpoints.token, params, token_response, http_code, &errmsg))
	{
		Server->Log("OIDC token request failed: " + errmsg, LL_ERROR);
		logFailedLogin(helper, PARAMS, "sso", LoginMethod_Webinterface);
		ret.set("success", false);
		ret.set("oidc_error", std::string("SSO login failed"));
		helper.Write(ret.stringify(false));
		return;
	}

	std::string access_token;
	if (!jsonGetString(token_response, "access_token", access_token) || access_token.empty())
	{
		Server->Log("OIDC token response has no access_token", LL_ERROR);
		ret.set("success", false);
		ret.set("oidc_error", std::string("SSO login failed"));
		helper.Write(ret.stringify(false));
		return;
	}

	str_map uparams;
	uparams["timeout"] = "20";
	uparams["addheader"] = "Authorization: Bearer " + access_token;
	std::string userinfo;
	if (!url_fak->requestUrl(endpoints.userinfo, uparams, userinfo, http_code, &errmsg))
	{
		Server->Log("OIDC userinfo request failed: " + errmsg, LL_ERROR);
		ret.set("success", false);
		ret.set("oidc_error", std::string("SSO login failed"));
		helper.Write(ret.stringify(false));
		return;
	}

	std::string preferred_username, display_name;
	jsonGetString(userinfo, "preferred_username", preferred_username);
	jsonGetString(userinfo, "name", display_name);

	preferred_username = strlower(trim(preferred_username));
	if (preferred_username.empty())
	{
		Server->Log("OIDC userinfo has no preferred_username", LL_ERROR);
		ret.set("success", false);
		ret.set("oidc_error", std::string("SSO account has no username"));
		helper.Write(ret.stringify(false));
		return;
	}

	std::string username = std::string(SSO_PREFIX) + preferred_username;

	bool admin_exists = true;
	int user_id = getOrCreateUser(helper.getDatabase(), username, admin_exists);
	if (user_id < 0)
	{
		Server->Log("SSO login of " + username + " denied: create a local admin user first", LL_ERROR);
		logFailedLogin(helper, PARAMS, username, LoginMethod_Webinterface);
		ret.set("success", false);
		ret.set("oidc_error", std::string("Create a local administrator user first, then sign in with SSO"));
		helper.Write(ret.stringify(false));
		return;
	}

	std::string ses = helper.generateSession("anonymous");
	POST["ses"] = ses;
	helper.update(tid, &POST, &PARAMS);

	SUser* session = helper.getSession();
	if (session == NULL)
	{
		ret.set("success", false);
		ret.set("error", 1);
		helper.Write(ret.stringify(false));
		return;
	}

	logSuccessfulLogin(helper, PARAMS, username, LoginMethod_Webinterface);
	session->mStr["login"] = "ok";
	session->mStr["username"] = username;
	session->id = user_id;

	// Kept server side so that logout can end the Keycloak session (id_token_hint)
	std::string id_token;
	if (jsonGetString(token_response, "id_token", id_token))
	{
		session->mStr["oidc_id_token"] = id_token;
	}

	ret.set("success", true);
	ret.set("session", JSON::Value(ses));
	ret.set("username", username);
	ret.set("display_name", display_name.empty() ? preferred_username : display_name);
	ret.set("status", helper.getRights("status"));
	ret.set("graph", helper.getRights("piegraph"));
	ret.set("progress", helper.getRights("progress"));
	ret.set("browse_backups", helper.getRights("browse_backups"));
	ret.set("settings", helper.getRights("settings"));
	ret.set("logs", helper.getRights("logs"));

	helper.Write(ret.stringify(false));
}

#endif //CLIENT_ONLY
