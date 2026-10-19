// Single sign-on (OpenID Connect / Keycloak) for the web interface.
//
// The authorization code flow with PKCE runs in the UrBackup server (action
// "oidc_login"), which also holds the client secret. The browser only gets the
// authorization URL and, after the redirect back, trades `code` + `state` for a
// normal UrBackup session.
//
// Hooks into urbackup.js:
//   g.sso_before_login(cb)  startup(): finishes a redirect from the provider,
//                           signs in silently when embedded, then calls cb
//   g.sso_take_pending()    try_anonymous_login(): the session from the redirect
//   g.sso_login_ui()        try_anonymous_login(): adds the SSO button
//   build_main_nav()        adds the "Log out" item (wrapped below)

(function ()
{
	var AUTO_ATTEMPT_KEY = "oidc_auto_attempt";
	var AUTO_ATTEMPT_PAUSE_MS = 15 * 1000;
	var SESSION_KEY = "ses";

	var pending = null;
	var message = "";

	function embedded()
	{
		try
		{
			return window.self !== window.top;
		}
		catch (e)
		{
			// reading window.top can throw for a cross-origin parent
			return true;
		}
	}

	// Flags from the host application travel in the hash (#sso=off, #sso_logout=1), not in the
	// query string: the web server takes a query string on a path without a "." for an action name
	function hashParam(name)
	{
		return new URLSearchParams(window.location.hash.replace(/^#/, "")).get(name);
	}

	function redirectUri()
	{
		return window.location.origin + window.location.pathname;
	}

	function post(params, cb)
	{
		$.ajax(
		{
			url: getURL("oidc_login"),
			dataType: "json",
			method: "POST",
			contentType: "application/json; charset=utf-8",
			data: params
		}).done(function (data) { cb(data); }).fail(function () { cb(null); });
	}

	function storeSession(ses)
	{
		try { sessionStorage.setItem(SESSION_KEY, ses); } catch (e) { }
	}

	function takeStoredSession()
	{
		try
		{
			var ses = sessionStorage.getItem(SESSION_KEY) || "";
			sessionStorage.removeItem(SESSION_KEY);
			return ses;
		}
		catch (e)
		{
			return "";
		}
	}

	function start(silent, cb)
	{
		post("step=start&redirect_uri=" + encodeURIComponent(redirectUri()), function (data)
		{
			if (!data || !data.success || !data.url)
			{
				message = (data && data.oidc_error) || "SSO login failed";
				cb(false);
				return;
			}

			if (!silent && embedded())
			{
				// The provider's login pages refuse to be framed: continue in a new tab
				window.open(data.url, "_blank", "noopener");
				cb(true);
				return;
			}

			window.location.assign(silent ? data.url + "&prompt=none" : data.url);
			cb(true);
		});
	}

	function showMessage()
	{
		var el = I("sso_message");
		if (el)
		{
			el.textContent = message;
			el.style.display = message ? "block" : "none";
		}
	}

	// ITSM logs out by loading the UI in a hidden frame with #sso_logout=1
	function handleLogoutRequest()
	{
		if (!embedded()) return false;
		if (hashParam("sso_logout") !== "1") return false;

		var ses = takeStoredSession();
		post("step=logout&ses=" + encodeURIComponent(ses), function () { });
		return true;
	}

	// Returns true if the page is being redirected
	function autoSsoIfEmbedded(cb)
	{
		if (!embedded()) return false;

		// The host application asks for the normal login page, e.g. ITSM for a user
		// that did not sign in with SSO, who must not get whoever the SSO session belongs to
		if (hashParam("sso") === "off") return false;

		try
		{
			// The stamp stops a redirect loop when the silent login fails
			var last = Number(sessionStorage.getItem(AUTO_ATTEMPT_KEY) || "0");
			if (Date.now() - last < AUTO_ATTEMPT_PAUSE_MS) return false;
			sessionStorage.setItem(AUTO_ATTEMPT_KEY, String(Date.now()));
		}
		catch (e)
		{
			return false;
		}

		post("step=config", function (data)
		{
			if (data && data.oidc_enabled)
			{
				start(true, function (ok) { if (!ok) cb(); });
			}
			else
			{
				cb();
			}
		});
		return true;
	}

	// Finishes a redirect back from the provider, then calls cb
	g.sso_before_login = function (cb)
	{
		if (handleLogoutRequest()) return;

		var q = new URLSearchParams(window.location.search);
		var code = q.get("code");
		var state = q.get("state");
		var error = q.get("error");

		if (state && (code || error))
		{
			// Do not keep the one-time code in the address bar
			window.history.replaceState(null, "", window.location.pathname + window.location.hash);

			// A proper answer from the provider (not a bounce without state), so a later
			// load, e.g. after the host application renewed the SSO session, may retry
			try { sessionStorage.removeItem(AUTO_ATTEMPT_KEY); } catch (e) { }

			if (error)
			{
				if (error === "login_required" || error === "interaction_required")
				{
					message = "No active SSO session. Sign in with SSO and reload this page, or use the SSO button to log in in a new tab.";
					// Lets the host application (ITSM) renew the SSO session and reload this page
					if (embedded())
					{
						window.parent.postMessage({ type: "urbackup-sso-required" }, "*");
					}
				}
				else
				{
					message = q.get("error_description") || error;
				}
				cb();
				return;
			}

			post("step=callback&code=" + encodeURIComponent(code) + "&state=" + encodeURIComponent(state), function (data)
			{
				if (data && data.success && data.session)
				{
					pending = data;
				}
				else
				{
					message = (data && data.oidc_error) || "SSO login failed";
				}
				cb();
			});
			return;
		}

		if (autoSsoIfEmbedded(cb)) return;

		cb();
	};

	g.sso_take_pending = function ()
	{
		var p = pending;
		pending = null;
		return p;
	};

	g.sso_login_ui = function ()
	{
		var form = document.forms["login1"];
		if (!form || I("sso_login_btn")) return;

		post("step=config", function (data)
		{
			if (!form.parentNode || I("sso_login_btn")) return;

			if (!(data && data.oidc_enabled) && !message) return;

			var box = document.createElement("div");
			box.innerHTML = '<div class="alert alert-warning" id="sso_message" style="display:none"></div>';
			form.parentNode.appendChild(box);

			if (data && data.oidc_enabled)
			{
				// Next to the Login button, on its right
				var login_btn = form.querySelector("button[type=submit]");
				var btn = document.createElement("button");
				btn.type = "button";
				btn.id = "sso_login_btn";
				btn.className = "btn btn-primary pull-right";
				btn.textContent = "Log in with SSO";
				btn.onclick = function ()
				{
					message = "";
					showMessage();
					start(false, function (ok) { if (!ok) showMessage(); });
				};
				login_btn.parentNode.insertBefore(btn, login_btn);
			}
			showMessage();
		});
	};

	g.sso_logout = function ()
	{
		var ses = g.session || "";
		post("step=logout&ses=" + encodeURIComponent(ses), function ()
		{
			g.session = "";
			g.allowed_nav_items = [];
			I("main_nav").innerHTML = "";
			I("nav_pos").innerHTML = "";
			startup();
		});
	};

	// Add "Log out" to the navigation (the host application owns the session when embedded)
	var orig_build_main_nav = build_main_nav;
	build_main_nav = function ()
	{
		orig_build_main_nav();
		if (!embedded())
		{
			var li = document.createElement("li");
			li.innerHTML = '<a href="javascript: g.sso_logout()">Log out</a>';
			I("main_nav").appendChild(li);
		}
	};

	// Remember the session of an embedded UI so that ITSM can end it with #sso_logout=1
	var orig_login3 = login3;
	login3 = function (data)
	{
		orig_login3(data);
		if (embedded() && data && data.session) storeSession(data.session);
	};

	// Embedded in ITSM the host application owns the branding
	if (embedded())
	{
		var style = document.createElement("style");
		style.textContent = ".navbar-brand { display: none !important; }";
		document.head.appendChild(style);
	}
})();
