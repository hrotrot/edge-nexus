import { connect } from "cloudflare:sockets";
const CURRENT_VERSION = '3.2.0';
const UPDATE_FIX = "constsCURRENT_VERSION='d.d.d'";
const __CYRUS_WORKER__ = (function (connect) {

const GLOBAL_TRAFFIC_CACHE = new Map();
const ACTIVE_CONNECTIONS_COUNT = new Map();
const GLOBAL_LAST_ACTIVE_WRITE = new Map();
const GLOBAL_LAST_DB_WRITE = new Map();
const GLOBAL_WRITE_LOCK = new Map();
const DNS_CACHE = new Map();
const USER_REQ_CACHE = new Map();
const LOGIN_ATTEMPTS = new Map(); 
let GLOBAL_REQ_COUNT = 0;
let GLOBAL_LAST_REQ_WRITE = 0;
const DNS_CACHE_TTL = 5 * 60 * 1000;
const DOH_RESOLVER = "https://cloudflare-dns.com/dns-query";
const UPSTREAM_BUNDLE_TARGET_BYTES = 16 * 1024;
const UPSTREAM_QUEUE_MAX_BYTES = 16 * 1024 * 1024;
const UPSTREAM_QUEUE_MAX_ITEMS = 4096;
const DOWNSTREAM_GRAIN_BYTES = 32 * 1024;
const DOWNSTREAM_GRAIN_TAIL_THRESHOLD = 512;
const DOWNSTREAM_GRAIN_SILENT_MS = 1;
const TCP_CONCURRENCY = 2;
const PRELOAD_RACE_DIAL = true;
let localLastAutoResetCheck = 0;
async function checkAutoResets(env) {
	const now = Date.now();
	if (now - localLastAutoResetCheck < 3600000) return;
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_auto_reset_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 3600000) {
			localLastAutoResetCheck = dbLastCheck;
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_auto_reset_check', ?)").bind(String(now)).run();
		localLastAutoResetCheck = now;

		const todayUtc = Math.floor(now / 86400000) * 86400000;
		await env.DB.prepare(`UPDATE users SET used_gb = 0, is_active = 1, last_reset_vol_time = ? WHERE auto_reset_vol_days > 0 AND ? >= (last_reset_vol_time + (auto_reset_vol_days * 86400000))`).bind(todayUtc, todayUtc).run();
		await env.DB.prepare(`UPDATE users SET used_req = 0, is_active = 1, last_reset_req_time = ? WHERE auto_reset_req_days > 0 AND ? >= (last_reset_req_time + (auto_reset_req_days * 86400000))`).bind(todayUtc, todayUtc).run();
	} catch (e) {}
}
let IP_FEED_CACHE = null;
let IP_FEED_CACHE_TS = 0;
const IP_FEED_TTL = 5 * 60 * 1000;
function ipFeedUrl(env) {
	return (env && env.IP_FEED_URL && env.IP_FEED_URL.trim()) ? env.IP_FEED_URL.trim() : "https://raw.githubusercontent.com/hrotrot/edge-nexus/main/ips.txt";
}
function isIpv4Line(s) {
	return /^(\d{1,3})(\.\d{1,3}){3}$/.test(s) || /^(?=.{1,253}$)([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/.test(s);
}
async function fetchIpFeed(env) {
	const now = Date.now();
	if (IP_FEED_CACHE && now - IP_FEED_CACHE_TS < IP_FEED_TTL) return IP_FEED_CACHE;
	try {
		const res = await fetch(ipFeedUrl(env) + "?t=" + now);
		if (!res.ok) return IP_FEED_CACHE || {};
		const text = await res.text();
		const blocks = text.split("----------");
		const parsed = {};
		blocks.forEach((block) => {
			const lines = block.trim().split("\n").map((l) => l.trim()).filter((l) => l.length > 0);
			if (lines.length === 0) return;
			let opName = "Unknown";
			const ips = [];
			lines.forEach((line) => {
				if (line.includes("#")) opName = line.split("#")[1].trim();
				else if (!line.startsWith("[source") && isIpv4Line(line)) ips.push(line);
			});
			if (ips.length > 0) parsed[opName] = ips;
		});
		IP_FEED_CACHE = parsed;
		IP_FEED_CACHE_TS = now;
		return parsed;
	} catch (e) {
		return IP_FEED_CACHE || {};
	}
}
function selectBlockIps(blockIps, count) {
	let availableIps = [...new Set(blockIps || [])];
	if (availableIps.length === 0) return [];
	if (count >= availableIps.length) return availableIps;
	const shuffled = availableIps.slice();
	for (let i = shuffled.length - 1; i > 0; i--) {
		const j = Math.floor(Math.random() * (i + 1));
		[shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
	}
	return shuffled.slice(0, count);
}
function selectIpsForOperator(cachedIpsData, operator, count) {
	if (!operator || operator === "all") {
		let pool = [];
		Object.values(cachedIpsData).forEach((ips) => (pool = pool.concat(ips)));
		return selectBlockIps(pool, count);
	}
	if (cachedIpsData[operator]) {
		return selectBlockIps(cachedIpsData[operator], count);
	}
	const opHeaders = Object.keys(cachedIpsData);
	const matchedHeader = opHeaders.find((h) => h.includes(operator) && !h.includes("دامنه"));
	if (matchedHeader) {
		return selectBlockIps(cachedIpsData[matchedHeader], count);
	}
	let pool = [];
	const general = opHeaders.find((h) => h.includes("ایران") && !h.includes("دامنه"));
	if (general) pool = cachedIpsData[general];
	else Object.values(cachedIpsData).forEach((ips) => (pool = pool.concat(ips)));
	return selectBlockIps(pool, count);
}
let localLastIpRotateCheck = 0;
async function checkAutoRotates(env) {
	const now = Date.now();
	if (now - localLastIpRotateCheck < 60000) return;
	try {
		const row = await env.DB.prepare("SELECT value FROM settings WHERE key = 'last_ip_rotate_check'").first();
		const dbLastCheck = row ? parseInt(row.value) || 0 : 0;
		if (now - dbLastCheck < 60000) {
			localLastIpRotateCheck = dbLastCheck;
			return;
		}
		await env.DB.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('last_ip_rotate_check', ?)").bind(String(now)).run();
		localLastIpRotateCheck = now;

		const { results: usersToRotate } = await env.DB.prepare("SELECT * FROM users WHERE auto_rotate_ip = 1 AND ? >= (last_rotate_time + (rotate_time * 60000))").bind(now).all();
		if (!usersToRotate || usersToRotate.length === 0) return;
		const cachedIpsData = await fetchIpFeed(env);
		if (Object.keys(cachedIpsData).length === 0) return;
		const stmts = [];
		for (const u of usersToRotate) {
			let count = u.ip_count || 100;
			let selectedIps = selectIpsForOperator(cachedIpsData, u.ip_operator || "all", count);
			if (selectedIps.length > 0) {
				stmts.push(env.DB.prepare("UPDATE users SET ips = ?, last_rotate_time = ? WHERE id = ?").bind(selectedIps.join("\n"), now, u.id));
			}
		}
		if (stmts.length > 0) {
			const batchSize = 50;
			for (let i = 0; i < stmts.length; i += batchSize) {
				await env.DB.batch(stmts.slice(i, i + batchSize));
			}
		}
	} catch (e) {}
}
let cachedVipCountries = [];
let lastVipCountriesFetch = 0;
async function replaceBrokenProxy(username, env, oldProxy) {
	try {
		if (GLOBAL_WRITE_LOCK.get(username + "_proxy_rotate")) return;
		GLOBAL_WRITE_LOCK.set(username + "_proxy_rotate", true);
		const user = await env.DB.prepare("SELECT id, user_socks5, auto_rotate_user_proxy FROM users WHERE username = ?").bind(username).first();
		if (!user || user.auto_rotate_user_proxy !== 1 || user.user_socks5 !== oldProxy) {
			GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
			return;
		}
		let countryCode = "all";
		try {
			let remain = oldProxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
			if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
			if (remain.startsWith("[")) remain = remain.substring(1, remain.indexOf("]"));
			else if (remain.includes(":")) remain = remain.substring(0, remain.lastIndexOf(":"));
			const geoRes = await fetch(`http://ip-api.com/json/${remain}?fields=countryCode`);
			const geoData = await geoRes.json();
			if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
		} catch (e) {}
		let newProxy = null;
		const upperCountry = countryCode.toUpperCase();
		const sources = [];
		const isOldProxyVIP = oldProxy.includes("@");
		if (cachedVipCountries.length === 0 || Date.now() - lastVipCountriesFetch > 3600000) {
			try {
				const ghRes = await fetch("https://updates.cyruspanel.local/vip-list", {
					headers: { "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" }
				});
				if (ghRes.ok) {
					const files = await ghRes.json();
					cachedVipCountries = files.filter(f => f.name.endsWith('.txt')).map(f => f.name.replace('.txt', '').toUpperCase());
					lastVipCountriesFetch = Date.now();
				}
			} catch (e) {}
		}
		let fallbackVIPs = cachedVipCountries.length > 0 ? [...cachedVipCountries] : ["DE", "US", "GB", "NL", "FR", "TR"];
		for (let i = fallbackVIPs.length - 1; i > 0; i--) {
			const j = Math.floor(Math.random() * (i + 1));
			[fallbackVIPs[i], fallbackVIPs[j]] = [fallbackVIPs[j], fallbackVIPs[i]];
		}
		if (upperCountry !== "ALL" && upperCountry !== "UN") {
			sources.push({ url: `https://updates.cyruspanel.local/proxy_vip/${upperCountry}.txt`, type: 'repo' });
		}
		for (const fc of fallbackVIPs) {
			if (fc !== upperCountry) {
				sources.push({ url: `https://updates.cyruspanel.local/proxy_vip/${fc}.txt`, type: 'repo' });
			}
		}
		if (!isOldProxyVIP) {
			if (upperCountry !== "ALL" && upperCountry !== "UN") {
				sources.push({ url: `https://updates.cyruspanel.local/proxy/${upperCountry}.txt`, type: 'repo' });
			}
			sources.push({ url: `https://updates.cyruspanel.local/proxy/ALL.txt`, type: 'repo' });
		}
		for (const src of sources) {
			try {
				const res = await fetch(src.url);
				if (!res.ok) continue;
				const text = await res.text();
				const lines = text.split("\n").map(l => l.trim()).filter(l => l.length > 5);
				if (lines.length > 0) {
					for (let i = lines.length - 1; i > 0; i--) {
						const j = Math.floor(Math.random() * (i + 1));
						[lines[i], lines[j]] = [lines[j], lines[i]];
					}
					const testBatch = lines.slice(0, 3).flatMap(line => {
						if (line.match(/^(socks4|socks5|socks|http|https|tg):\/\//i) || line.includes("t.me/socks")) {
							return [line];
						}
						if (src.type === 'socks5') return [`socks5://${line}`];
						if (src.type === 'http') return [`http://${line}`];
						return [`socks5://${line}`, `http://${line}`];
					});
					try {
						newProxy = await Promise.any(testBatch.map(p => {
							return new Promise(async (resolve, reject) => {
								const timeoutId = setTimeout(() => reject(new Error('timeout')), 3000); 
								try {
									const payload = new TextEncoder().encode("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n");
									const s = await connectProxy(p, "1.1.1.1", 80, payload);
									const reader = s.readable.getReader();
									const res = await reader.read();
									s.close();
									clearTimeout(timeoutId);
									if (res.done || !res.value) reject(new Error("empty"));
									else resolve(p);
								} catch (e) {
									clearTimeout(timeoutId);
									reject(e);
								}
							});
						}));
					} catch (e) {
						continue;
					}
					if (newProxy) {
						break; 
					}
				}
			} catch (e) {}
		}
		if (newProxy) {
			await env.DB.prepare("UPDATE users SET user_socks5 = ? WHERE id = ?").bind(newProxy, user.id).run();
		}
	} catch(e) {
	} finally {
		GLOBAL_WRITE_LOCK.delete(username + "_proxy_rotate");
	}
}
const __WORKER_EXPORT__ = {
	async fetch(request, env, ctx) {
		if (!env || !env.DB) {
			return new Response("Database binding 'DB' is missing in Cloudflare Workers settings.", { status: 500 });
		}
		try {
			try {
				await DbService.ensureSchema(env.DB);
				await DbService.bootstrapDefaults(env.DB, env);
			} catch (e) {
				console.error("[DbInit]", e);
			}
			trackRequest(env, ctx);
			if (schemaEnsured && ctx) {
				ctx.waitUntil((async () => {
					try { await checkAutoResets(env); } catch (e) {}
					try { await checkAutoRotates(env); } catch (e) {}
				})());
			}
			const url = new URL(request.url);
			if (Router.isWebSocketUpgrade(request)) {
				return await Router.handleWebSocket(request, env, ctx);
			}
			if (Router.isSubscriptionPath(url.pathname)) {
				return await Router.handleSubscription(url, env);
			}
			const redirectTarget = (env && env.REDIRECT_URL && env.REDIRECT_URL.trim()) ? env.REDIRECT_URL.trim() : "https://t.me/kouroshasli";
			return new Response(`<!DOCTYPE html><html><head><meta http-equiv="refresh" content="0; url=${redirectTarget}"><script>window.location.replace("${redirectTarget}");</script><title>Redirecting...</title></head><body>Redirecting to <a href="${redirectTarget}">${redirectTarget}</a></body></html>`, {
				status: 302,
				headers: {
					"Location": redirectTarget,
					"Content-Type": "text/html; charset=utf-8",
					"Cache-Control": "no-cache, no-store, must-revalidate",
				},
			});
		} catch (err) {
			console.error("[Worker Error]", err);
			let msg = (err && err.message) || String(err);
			if (msg.toLowerCase().includes("d1") && (msg.toLowerCase().includes("limit") || msg.toLowerCase().includes("exceeded") || msg.toLowerCase().includes("daily row") || msg.toLowerCase().includes("quota"))) {
				return new Response(JSON.stringify({ error: "سهمیه دیتابیس شما به سقف مجاز کلودفلر رسیده است و ساعت 3:30 ریست می‌شود." }), { 
					status: 500, 
					headers: { "Content-Type": "application/json; charset=utf-8" } 
				});
			}
			return new Response("Internal Server Error", { status: 500 });
		}
	},
};
const Router = {
	isWebSocketUpgrade(request) {
		const upgradeHeader = (request.headers.get("Upgrade") || "").toLowerCase();
		return upgradeHeader === "websocket";
	},
	isSubscriptionPath(pathname) {
		return pathname.startsWith("/sub/") || pathname.startsWith("/subt/") || pathname.startsWith("/feed/") || pathname.startsWith("/suball/") || pathname.startsWith("/singbox/");
	},
	async handleWebSocket(request, env, ctx) {
		try {
			let proxyIP = "";
			let socks5 = "";
			try {
				const proxyRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'proxy_ip'").first();
				if (proxyRow && proxyRow.value) {
					proxyIP = proxyRow.value;
				}
				const socksRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'socks5'").first();
				if (socksRow && socksRow.value) {
					socks5 = socksRow.value;
				}
			} catch (e) {}
			const mockStoredData = { proxy_ip: proxyIP, socks5: socks5 };
			return await handlevIees(env, mockStoredData, ctx, request);
		} catch (e) {
			return new Response("Internal Server Error", { status: 500 });
		}
	},
	async handleSubscription(url, env) {
		const isSubPath = url.pathname.startsWith("/sub/");
		const isSubtPath = url.pathname.startsWith("/subt/");
		const isFeedPath = url.pathname.startsWith("/feed/");
		const isSuballPath = url.pathname.startsWith("/suball/");
		const isSingboxPath = url.pathname.startsWith("/singbox/");
		const offset = isSingboxPath ? 9 : isSuballPath ? 8 : (isSubtPath || isFeedPath) ? 6 : isSubPath ? 5 : 6;
		let subUser = decodeURIComponent(url.pathname.slice(offset));
		const host = url.hostname;
		try {
			const user = await env.DB.prepare("SELECT * FROM users WHERE username = ? OR uuid = ?").bind(subUser, subUser).first();
			if (!user) {
				console.log(`[handleSubscription] 404: username="${subUser}" not found`);
				return new Response("Not Found", { status: 404 });
			}
			try {
				await env.DB.prepare("UPDATE users SET used_req = used_req + 1 WHERE username = ?").bind(user.username).run();
			} catch (e) {}
			if (isSingboxPath) {
				return await SubscriptionService.generateSingbox(user, host, env);
			}
			if (isSubtPath) {
				return await SubscriptionService.generateText(user, host, env, { mode: "trojan" });
			}
			if (url.pathname.startsWith("/feed/") || url.pathname.startsWith("/suball/")) {
				return await SubscriptionService.generateText(user, host, env, { mode: "all" });
			}
			return await SubscriptionService.generateText(user, host, env, { mode: "vl" + "e" + "ss" });
		} catch (err) {
			return new Response("Error building config: " + err.message, { status: 500 });
		}
	},
};

let schemaEnsured = false;
let schemaPromise = null;
let cachedPanelPassword = null;
let bootstrapDone = false;
const DbService = {
	async ensureSchema(db) {
		if (schemaEnsured) return;
		if (schemaPromise) {
			await schemaPromise;
			return;
		}
		schemaPromise = (async () => {
			try {
				await db.prepare(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, uuid TEXT, limit_gb REAL, expiry_days INTEGER, ips TEXT, connection_type TEXT, tls TEXT, port INTEGER, used_gb REAL DEFAULT 0, is_active INTEGER DEFAULT 1, last_active INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, fingerprint TEXT DEFAULT 'chrome', max_connections INTEGER, limit_req INTEGER, used_req INTEGER DEFAULT 0, ip_limit INTEGER DEFAULT NULL, active_ips TEXT DEFAULT NULL, block_porn INTEGER DEFAULT 0, block_ads INTEGER DEFAULT 1, frag_len TEXT DEFAULT '200-3000', frag_int TEXT DEFAULT '1-2', lifetime_used_gb REAL DEFAULT 0, user_proxy_ip TEXT DEFAULT NULL, user_proxy_iata TEXT DEFAULT NULL, user_socks5 TEXT DEFAULT NULL, auto_reset_vol_days INTEGER DEFAULT 0, auto_reset_req_days INTEGER DEFAULT 0, last_reset_vol_time INTEGER DEFAULT 0, last_reset_req_time INTEGER DEFAULT 0, auto_rotate_ip INTEGER DEFAULT 0, rotate_time INTEGER DEFAULT 0, ip_operator TEXT DEFAULT 'all', ip_count INTEGER DEFAULT 100, last_rotate_time INTEGER DEFAULT 0, auto_rotate_user_proxy INTEGER DEFAULT 0, advanced_frag TEXT DEFAULT NULL, cipher_suites TEXT DEFAULT NULL, tls_mask TEXT DEFAULT NULL)`).run();
			} catch (e) {}
			try {
				await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
			} catch (e) {}
			const colsToAdd = [
				{ name: "is_active", def: "INTEGER DEFAULT 1" },
				{ name: "last_active", def: "INTEGER" },
				{ name: "fingerprint", def: "TEXT DEFAULT 'chrome'" },
				{ name: "max_connections", def: "INTEGER" },
				{ name: "limit_req", def: "INTEGER" },
				{ name: "used_req", def: "INTEGER DEFAULT 0" },
				{ name: "ip_limit", def: "INTEGER DEFAULT NULL" },
				{ name: "active_ips", def: "TEXT DEFAULT NULL" },
				{ name: "block_porn", def: "INTEGER DEFAULT 0" },
				{ name: "block_ads", def: "INTEGER DEFAULT 1" },
				{ name: "frag_len", def: "TEXT DEFAULT '200-3000'" },
				{ name: "frag_int", def: "TEXT DEFAULT '1-2'" },
				{ name: "lifetime_used_gb", def: "REAL DEFAULT 0" },
				{ name: "user_proxy_ip", def: "TEXT DEFAULT NULL" },
				{ name: "user_proxy_iata", def: "TEXT DEFAULT NULL" },
				{ name: "user_socks5", def: "TEXT DEFAULT NULL" },
				{ name: "auto_reset_vol_days", def: "INTEGER DEFAULT 0" },
				{ name: "auto_reset_req_days", def: "INTEGER DEFAULT 0" },
				{ name: "last_reset_vol_time", def: "INTEGER DEFAULT 0" },
				{ name: "last_reset_req_time", def: "INTEGER DEFAULT 0" },
				{ name: "auto_rotate_ip", def: "INTEGER DEFAULT 0" },
				{ name: "rotate_time", def: "INTEGER DEFAULT 0" },
				{ name: "ip_operator", def: "TEXT DEFAULT 'all'" },
				{ name: "ip_count", def: "INTEGER DEFAULT 100" },
				{ name: "last_rotate_time", def: "INTEGER DEFAULT 0" },
				{ name: "auto_rotate_user_proxy", def: "INTEGER DEFAULT 0" },
				{ name: "advanced_frag", def: "TEXT DEFAULT NULL" },
				{ name: "cipher_suites", def: "TEXT DEFAULT NULL" },
				{ name: "tls_mask", def: "TEXT DEFAULT NULL" }
			];
			try {
				const { results } = await db.prepare("PRAGMA table_info(users)").all();
				const existingCols = new Set((results || []).map((r) => r.name));
				for (const col of colsToAdd) {
					if (existingCols.has(col.name)) continue;
					try {
						await db.prepare(`ALTER TABLE users ADD COLUMN ${col.name} ${col.def}`).run();
					} catch (e) {}
				}
			} catch (e) {}
			try {
				await db.prepare("UPDATE users SET ip_limit = max_connections WHERE ip_limit IS NULL AND max_connections IS NOT NULL").run();
			} catch (e) {}
			try {
				await db.prepare("UPDATE users SET lifetime_used_gb = used_gb WHERE lifetime_used_gb = 0 OR lifetime_used_gb IS NULL").run();
			} catch (e) {}
			schemaEnsured = true;
		})();
		try {
			await schemaPromise;
		} catch (e) {
			schemaPromise = null;
		}
	},
	async bootstrapDefaults(db, env) {
		if (bootstrapDone) return;
		if (!env || !env.BOOT_USERNAME) { bootstrapDone = true; return; }
		const username = env.BOOT_USERNAME;
		// FIX: drop any stale cached password (it may have been cached as
		// "empty" before the settings table/password existed) so bootstrap
		// always reads the fresh state from the database.
		cachedPanelPassword = null;
		// Panel self-configures its own password from the bot-provided value.
		if (env.BOOT_PASSWORD) {
			const existingPw = await this.getPanelPassword(db);
			if (!existingPw) {
				cachedPanelPassword = null;
				await this.setPanelPassword(db, await this.sha256(env.BOOT_PASSWORD));
			}
		}
		const existing = await db.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
		if (existing) {
			try {
				await db.prepare("UPDATE users SET connection_type = 'vless,trojan,shadowsocks' WHERE id = ?").bind(existing.id).run();
			} catch (e) {}
			bootstrapDone = true;
			return;
		}
		const rHex = Array.from(crypto.getRandomValues(new Uint8Array(6))).map((b) => b.toString(16).padStart(2, "0")).join("");
		const uuid = `43595255-535f-504e-4c5f-${rHex}`;
		const ips = env.BOOT_IPS || null;
		const ports = "443,2053,2083,8080,80,8880";
		const nowIso = new Date().toISOString();
		const todayUtc = Math.floor(Date.now() / 86400000) * 86400000;
		const nowTime = Date.now();
		const bootCt = String(env.BOOT_CONNECTION_TYPE || "vl" + "e" + "ss").toLowerCase();
		const bootCtValid = bootCt.includes("vl" + "e" + "ss") || bootCt.includes("trojan") ? bootCt : "vl" + "e" + "ss";
		try {
			await db.prepare("INSERT INTO users (username, uuid, limit_gb, expiry_days, limit_req, ips, connection_type, tls, port, fingerprint, max_connections, ip_limit, used_gb, used_req, created_at, is_active, block_porn, block_ads, frag_len, frag_int, user_proxy_iata, user_socks5, user_proxy_ip, auto_reset_vol_days, auto_reset_req_days, last_reset_vol_time, last_reset_req_time, auto_rotate_ip, rotate_time, ip_operator, ip_count, last_rotate_time, auto_rotate_user_proxy) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
				.bind(username, uuid, null, null, null, ips, bootCtValid, "on", ports, "unsafe", null, null, 0, 0, nowIso, 1, 0, 1, "200-3000", "1-2", null, null, null, 0, 0, todayUtc, todayUtc, 0, 0, (env.BOOT_OPERATOR || "all"), 10, nowTime, 0)
				.run();
		} catch (e) {
			throw new Error("bootstrapDefaults INSERT failed for user '" + username + "': " + (e && e.message ? e.message : String(e)));
		}
		bootstrapDone = true;
	},
	async getPanelPassword(db) {
		if (cachedPanelPassword !== null) return cachedPanelPassword;
		try {
			const row = await db.prepare("SELECT value FROM settings WHERE key = 'panel_password'").first();
			cachedPanelPassword = row ? row.value : "";
			return cachedPanelPassword || null;
		} catch (e) {
			return null;
		}
	},
	async setPanelPassword(db, password) {
		await db.prepare("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)").run();
		await db.prepare("INSERT OR REPLACE INTO settings (key, value) VALUES ('panel_password', ?)").bind(password).run();
		cachedPanelPassword = password;
	},
	async verifyApiAuth(request, env) {
		const storedPasswordHash = await this.getPanelPassword(env.DB);
		if (!storedPasswordHash) return true;
		const cookies = request.headers.get("Cookie") || "";
		const sessionCookie = cookies.split(";").find((c) => c.trim().startsWith("panel_session="));
		if (!sessionCookie) return false;
		const sessionToken = sessionCookie.split("=")[1].trim();
		return sessionToken === storedPasswordHash;
	},
	async sha256(message) {
		const msgBuffer = new TextEncoder().encode(message);
		const hashBuffer = await crypto.subtle.digest("SHA-256", msgBuffer);
		const hashArray = Array.from(new Uint8Array(hashBuffer));
		return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
	},
};
function getActiveIpCount(activeIpsJson) {
	if (!activeIpsJson) return 0;
	try {
		const activeIps = JSON.parse(activeIpsJson);
		const now = Date.now();
		let count = 0;
		for (const [ip, data] of Object.entries(activeIps)) {
			const lastSeen = data && typeof data === "object" ? data.timestamp : data;
			if (now - lastSeen <= 20000) {
				count++;
			}
		}
		return count;
	} catch (e) {
		return 0;
	}
}
let CACHED_CF_LOCATIONS = null;
let CACHED_CF_LOCATIONS_TIME = 0;
const DEFAULT_ADVANCED_FRAG = '{"tcp":[{"type":"fragment","settings":{"packets":"tlshello","lengths":["0","104","1"],"delays":["0"],"maxSplit":"0"}},{"type":"fragment","settings":{"packets":"1-1","lengths":["114","1"],"delays":["1"],"maxSplit":"11"}}]}';
const SubscriptionService = {
	async generateText(user, host, env, opts = {}) {
		const mode = opts.mode || "vl" + "e" + "ss";
		const isTrojanMode = mode === "trojan";
		const isVlessMode = mode === "vl" + "e" + "ss";
		const isAllMode = mode === "all";

		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await fetchIpFeed(env);
			const randomIps = selectIpsForOperator(cachedIpsData, user.ip_operator || "all", user.ip_count || 10);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}

		const ports = String(user.port || "443,2053,2083,8080,80,8880")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);

		// Always use modern Chrome TLS fingerprint like Zeus
		const fp = (user.fingerprint && user.fingerprint !== "unsafe") ? user.fingerprint : "chrome";

		// Dynamic Path extraction matching Zeus WebSocket router
		const uuidSuffix = user.uuid ? (user.uuid.split("-")[4] || user.uuid.split("-")[0]) : "default";
		const rawPath = "/stream/CYRUS_PANEL/" + uuidSuffix;
		const dynPath = encodeURIComponent(rawPath);

		const links = [];

		let countryCode = "";
		if (user.user_proxy_iata) {
			try {
				if (!CACHED_CF_LOCATIONS || Date.now() - CACHED_CF_LOCATIONS_TIME > 86400000) {
					const res = await fetch("https://speed.cloudflare.com/locations", {
						headers: { Referer: "https://speed.cloudflare.com/" },
					});
					if (res.ok) {
						CACHED_CF_LOCATIONS = await res.json();
						CACHED_CF_LOCATIONS_TIME = Date.now();
					}
				}
				if (CACHED_CF_LOCATIONS) {
					const found = CACHED_CF_LOCATIONS.find((l) => l.iata && l.iata.toUpperCase() === user.user_proxy_iata.toUpperCase());
					if (found && found.cca2) countryCode = found.cca2;
				}
			} catch (e) {}
		} else if (user.user_socks5 || user.user_proxy_ip) {
			let proxy = user.user_socks5 || user.user_proxy_ip;
			let ip = "";
			let cleanProxy = proxy.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
			let remain = cleanProxy;
			if (remain.includes("@")) remain = remain.substring(remain.lastIndexOf("@") + 1);
			if (remain.startsWith("[")) {
				ip = remain.substring(1, remain.indexOf("]"));
			} else {
				const lastColon = remain.lastIndexOf(":");
				if (lastColon !== -1 && remain.indexOf(":") === lastColon) ip = remain.substring(0, lastColon);
				else ip = remain;
			}
			if (ip) {
				try {
					const geoRes = await fetch(`http://ip-api.com/json/${ip}?fields=countryCode`);
					const geoData = await geoRes.json();
					if (geoData && geoData.countryCode) countryCode = geoData.countryCode;
				} catch (e) {}
			}
		}

		let flagEmoji = "⚡";
		if (countryCode) {
			const codePoints = countryCode
				.toUpperCase()
				.split("")
				.map((char) => 127397 + char.charCodeAt(0));
			try {
				flagEmoji = String.fromCodePoint(...codePoints);
			} catch (e) {}
		}

		// Dedicated endpoints ALWAYS generate the requested protocol:
		// mode "vless" -> VLESS
		// mode "trojan" -> Trojan
		// mode "all" -> VLESS + Trojan + Shadowsocks
		const enableVless = isVlessMode || isAllMode;
		const enableTrojan = isTrojanMode || isAllMode;
		const enableSS = isAllMode;

		// TLS Port sets matching Cloudflare standard edge
		const tlsPortSet = new Set(["443", "2053", "2083", "2087", "2096", "8443"]);

		ips.forEach((rawIp) => {
			let ip = String(rawIp).trim();
			const bMatch = ip.match(/^\[(.*?)\]/);
			if (bMatch) ip = bMatch[1];
			else if (ip.split(":").length === 2) ip = ip.split(":")[0];
			let safeIp = ip.includes(":") && !ip.startsWith("[") ? `[${ip}]` : ip;

			ports.forEach((portStr) => {
				const isTlsPort = tlsPortSet.has(portStr);
				const tlsVal = isTlsPort ? "tls" : "none";

				// Advanced Fragmentation & ECH exact Zeus parity
				let userFrag = "";
				const fragLen = user.frag_len || "10-20";
				const fragInt = user.frag_int || "10-20";
				userFrag += "&fragment=" + encodeURIComponent(fragLen + "," + fragInt + (isTlsPort ? ",tlshello" : ""));

				if (user.advanced_frag) userFrag += "&fm=" + encodeURIComponent(user.advanced_frag);
				if (isTlsPort && user.cipher_suites) userFrag += "&cs=" + encodeURIComponent(user.cipher_suites);
				if (user.tls_mask) userFrag += "&mask=" + encodeURIComponent(user.tls_mask);
				if (isTlsPort && user.ech) userFrag += "&ech=" + encodeURIComponent(user.ech);

				const tlsParams = isTlsPort ? ("&insecure=0&fp=" + fp + "&allowInsecure=0&sni=" + host) : "";

				if (enableVless) {
					const remark = "@CFsazbot & 👾 & VLESS & " + portStr;
					links.push("vl" + "e" + "ss://" + user.uuid + "@" + safeIp + ":" + portStr + "?path=" + dynPath + "&security=" + tlsVal + "&encryption=none&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(remark));
				}
				if (enableTrojan) {
					const trojanRemark = "@CFsazbot & 👾 & Trojan & " + portStr;
					links.push("trojan://" + user.uuid + "@" + safeIp + ":" + portStr + "?path=" + dynPath + "&security=" + tlsVal + "&host=" + host + "&type=ws" + tlsParams + userFrag + "#" + encodeURIComponent(trojanRemark));
				}
				if (enableSS) {
					const ssRemark = "@CFsazbot & 👾 & SS & " + portStr;
					const methodPass = btoa("aes-256-gcm:" + user.uuid);
					let pluginOpts = "v2ray-plugin;mode=websocket;host=" + host + ";path=" + decodeURIComponent(dynPath) + (isTlsPort ? ";tls" : "");
					links.push("ss://" + methodPass + "@" + safeIp + ":" + portStr + "/?plugin=" + encodeURIComponent(pluginOpts) + "#" + encodeURIComponent(ssRemark));
				}
			});
		});

		const subTitleB64 = "base64:" + btoa(unescape(encodeURIComponent("⚡@CFsazbot")));
		const subWebPageUrl = "https://t.me/CFsazbot";
		const noise = [
			"#profile-title: " + subTitleB64,
			"#profile-web-page-url: " + subWebPageUrl,
			"#support-url: " + subWebPageUrl,
			"#profile-update-interval: 12",
			"# System Update Feed: OK",
			"# Sync Code: " + Math.random().toString(36).slice(2, 10),
			"# Version: 2.10.1",
			"# Description: High Performance V2Ray Node",
			""
		].join("\n");

		const plainContent = noise + links.join("\n");
		const subContent = btoa(unescape(encodeURIComponent(plainContent)));

		const downloadBytes = Math.floor((user.used_gb || 0) * 1073741824);
		const totalBytes = user.limit_gb ? Math.floor(user.limit_gb * 1073741824) : 0;
		let expireTimestamp = 0;
		if (user.expiry_days && user.created_at) {
			expireTimestamp = Math.floor((new Date(user.created_at).getTime() + user.expiry_days * 86400000) / 1000);
		}

		const subUserInfo = `upload=0; download=${downloadBytes}; total=${totalBytes}; expire=${expireTimestamp}`;
		return new Response(subContent, {
			headers: {
				"Content-Type": "text/plain; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
				"Subscription-Userinfo": subUserInfo,
			},
		});
	},
	async generateSingbox(user, host, env) {
		let ips = [host];
		if (user.auto_rotate_ip === 1) {
			const cachedIpsData = await fetchIpFeed(env);
			const randomIps = selectIpsForOperator(cachedIpsData, user.ip_operator || "all", user.ip_count || 10);
			if (randomIps.length > 0) ips = randomIps;
		}
		if (ips.length === 1 && ips[0] === host && user.ips) {
			const parsedIps = user.ips
				.split("\n")
				.map((ip) => ip.trim())
				.filter((ip) => ip.length > 0);
			if (parsedIps.length > 0) ips = parsedIps;
		}
		const ports = String(user.port || "443,2053,2083,8080,80,8880")
			.split(",")
			.map((p) => p.trim())
			.filter((p) => p.length > 0);
		const fp = user.fingerprint || "chrome";
		const safeFp = fp === "unsafe" ? "chrome" : fp;
		const rawPath = "/stream/CYRUS_PANEL/" + (user.uuid ? user.uuid.split("-")[0] : "default");
		const outbounds = [];
		const ct = String(user.connection_type || "vl" + "e" + "ss").toLowerCase();
		const enableVless = ct.includes("vl" + "e" + "ss") || ct === "vl" + "e" + "ss" || !ct.includes("trojan");
		const enableTrojan = ct.includes("trojan");
		const sni = user.tls_mask || host;
		ips.forEach((ip) => {
			ports.forEach((portStr) => {
				const isTlsPort = ["443", "2053", "2083", "2087", "2096", "8443"].includes(portStr);
				if (enableVless) {
					let outbound = {
						type: "vl" + "e" + "ss",
						tag: "CFsazbot-VLESS-" + ip + "-" + portStr,
						server: ip,
						server_port: parseInt(portStr),
						uuid: user.uuid,
						packet_encoding: "xudp",
						transport: {
							type: "ws",
							path: rawPath,
							headers: { Host: host },
						},
					};
					if (isTlsPort) {
						outbound.tls = {
							enabled: true,
							server_name: sni,
							insecure: false,
							utls: { enabled: true, fingerprint: safeFp },
						};
					}
					outbounds.push(outbound);
				}
				if (enableTrojan) {
					let outbound = {
						type: "trojan",
						tag: "CFsazbot-Trojan-" + ip + "-" + portStr,
						server: ip,
						server_port: parseInt(portStr),
						password: user.uuid,
						transport: {
							type: "ws",
							path: rawPath,
							headers: { Host: host },
						},
					};
					if (isTlsPort) {
						outbound.tls = {
							enabled: true,
							server_name: sni,
							insecure: false,
							utls: { enabled: true, fingerprint: safeFp },
						};
					}
					outbounds.push(outbound);
				}
			});
		});
		const outboundsList = outbounds.map((o) => o.tag);
		let targetDns = "udp://8.8.8.8";
		if (user.block_porn === 1 && user.block_ads === 1) {
			targetDns = "udp://94.140.14.15";
		} else if (user.block_porn === 1) {
			targetDns = "udp://1.1.1.3";
		} else if (user.block_ads === 1) {
			targetDns = "udp://94.140.14.14";
		}
		const config = {
			log: { disabled: false, level: "info" },
			dns: {
				servers: [
					{
						tag: "remote-dns",
						address: targetDns,
						detour: outboundsList.length > 0 ? "proxy" : "direct",
					},
				],
				final: "remote-dns",
				independent_cache: true,
			},
			inbounds: [
				{
					type: "tun",
					tag: "tun-in",
					interface_name: "tun0",
					address: ["172.19.0.1/30", "fdfe:dcba:9876::1/126"],
					auto_route: true,
					strict_route: true,
					stack: "mixed",
				},
			],
			outbounds: [
				{
					type: "selector",
					tag: "proxy",
					outbounds: outboundsList.length > 0 ? outboundsList : ["direct"],
				},
				{
					type: "direct",
					tag: "direct",
				},
				{
					type: "block",
					tag: "block",
				},
				{
					type: "dns-out",
					tag: "dns-out",
				},
				...outbounds,
			],
			route: {
				rules: [
					{ protocol: "dns", outbound: "dns-out" },
					{ geoip: "cn", outbound: "block" },
					{ geoip: "private", outbound: "direct" },
				],
				auto_detect_interface: true,
				final: "proxy",
			},
		};
		return new Response(JSON.stringify(config, null, 2), {
			headers: {
				"Content-Type": "application/json; charset=utf-8",
				"Access-Control-Allow-Origin": "*",
				"Cache-Control": "no-store",
			},
		});
	},
};
async function flushExpiredTraffic(env) {
	const now = Date.now();
	for (const [key, val] of DNS_CACHE.entries()) {
		if (now > val.expires) DNS_CACHE.delete(key);
	}
	for (const [ip, record] of LOGIN_ATTEMPTS.entries()) {
		if (now - record.lastAttempt > 900000) LOGIN_ATTEMPTS.delete(ip);
	}
	const allUsers = new Set([...GLOBAL_TRAFFIC_CACHE.keys(), ...USER_REQ_CACHE.keys()]);
	for (const uname of allUsers) {
		const cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
		const cachedReqs = USER_REQ_CACHE.get(uname) || 0;
		const activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (cachedBytes <= 0 && cachedReqs <= 0) {
			GLOBAL_TRAFFIC_CACHE.delete(uname);
			USER_REQ_CACHE.delete(uname);
			if (activeCount <= 0) {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
			}
			continue;
		}
		if (GLOBAL_WRITE_LOCK.get(uname)) continue;
		const lastActive = GLOBAL_LAST_ACTIVE_WRITE.get(uname) || 0;
		if (activeCount <= 0 || now - lastActive > 20000) {
			GLOBAL_WRITE_LOCK.set(uname, true);
			GLOBAL_TRAFFIC_CACHE.set(uname, 0);
			USER_REQ_CACHE.set(uname, 0);
			const deltaGb = cachedBytes / (1024 * 1024 * 1024);
			try {
				await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
			} catch (e) {
				console.error(e.message);
			} finally {
				GLOBAL_WRITE_LOCK.delete(uname);
				if (activeCount <= 0) {
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					GLOBAL_LAST_ACTIVE_WRITE.delete(uname + "_hb");
				}
			}
		}
	}
}
async function handlevIees(env, storedData = null, ctx = null, request = null) {
	const clientIP = request ? request.headers.get("CF-Connecting-IP") || "unknown" : "unknown";
	const socketPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(socketPair);
	serverSock.accept();
	serverSock.binaryType = "arraybuffer";
	let username = null;
	let validUUID = null;
	let targetDns = "8.8.4.4";
	let targetDoh = "https://cloudflare-dns.com/dns-query";
	function addBytes(bytes) {
		if (bytes <= 0) return;
		if (!username) {
			uncountedBytes += bytes;
			return;
		}
		if (uncountedBytes > 0) {
			bytes += uncountedBytes;
			uncountedBytes = 0;
		}
		let current = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
		GLOBAL_TRAFFIC_CACHE.set(username, current + bytes);
		GLOBAL_LAST_ACTIVE_WRITE.set(username, Date.now());
		if (GLOBAL_WRITE_LOCK.get(username)) return;
		let lastDbWrite = GLOBAL_LAST_DB_WRITE.get(username) || 0;
		let now = Date.now();
		let thresholdBytes = 10 * 1024 * 1024;
		if (current >= thresholdBytes || (current > 0 && now - lastDbWrite > 60000)) {
			GLOBAL_WRITE_LOCK.set(username, true);
			let toCommit = GLOBAL_TRAFFIC_CACHE.get(username) || 0;
			let toCommitReq = USER_REQ_CACHE.get(username) || 0;
			if (toCommit <= 0 && toCommitReq <= 0) {
				GLOBAL_WRITE_LOCK.set(username, false);
				return;
			}
			GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) - toCommit);
			USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) - toCommitReq);
			GLOBAL_LAST_DB_WRITE.set(username, now);
			let deltaGb = toCommit / (1024 * 1024 * 1024);
			let writeTask = async () => {
				try {
					await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, toCommitReq, username).run();
				} catch (e) {
					console.error(e.message);
					GLOBAL_TRAFFIC_CACHE.set(username, (GLOBAL_TRAFFIC_CACHE.get(username) || 0) + toCommit);
					USER_REQ_CACHE.set(username, (USER_REQ_CACHE.get(username) || 0) + toCommitReq);
				} finally {
					GLOBAL_WRITE_LOCK.set(username, false);
				}
			};
			if (ctx) ctx.waitUntil(writeTask());
			else writeTask();
		}
	}
	let isOfflineSet = false;
	let hasCountedAsActive = false;
	const setOffline = () => {
		if (isOfflineSet) return;
		isOfflineSet = true;
		const uname = username;
		if (!uname) return;
		if (clientIP && clientIP !== "unknown" && validUUID) {
			const removeIpTask = async () => {
				try {
					const user = await env.DB.prepare("SELECT active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					if (user) {
						console.log(`[setOffline Task] DB active_ips for ${uname}: ${user.active_ips}`);
						let activeIps = JSON.parse(user.active_ips || "{}");
						if (activeIps[clientIP]) {
							if (typeof activeIps[clientIP] === "object") {
								activeIps[clientIP].count = (activeIps[clientIP].count || 1) - 1;
								if (activeIps[clientIP].count <= 0) {
									delete activeIps[clientIP];
								}
							} else {
								delete activeIps[clientIP];
							}
							await env.DB.prepare("UPDATE users SET active_ips = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), validUUID).run();
							console.log(`[setOffline Task] Updated active_ips in DB to: ${JSON.stringify(activeIps)}`);
						} else {
							console.log(`[setOffline Task] IP ${clientIP} not found in user's active_ips`);
						}
					}
				} catch (e) {
					console.error(`[setOffline Task] Error: ${e.message}`);
				}
			};
			if (ctx) ctx.waitUntil(removeIpTask());
			else removeIpTask();
		}
		let activeCount = ACTIVE_CONNECTIONS_COUNT.get(uname) || 0;
		if (hasCountedAsActive) {
			activeCount = Math.max(0, activeCount - 1);
		}
		if (activeCount <= 0) {
			ACTIVE_CONNECTIONS_COUNT.delete(uname);
			let cachedBytes = GLOBAL_TRAFFIC_CACHE.get(uname) || 0;
			let cachedReqs = USER_REQ_CACHE.get(uname) || 0;
			if ((cachedBytes > 0 || cachedReqs > 0) && !GLOBAL_WRITE_LOCK.get(uname)) {
				GLOBAL_WRITE_LOCK.set(uname, true);
				GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) - cachedBytes);
				USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) - cachedReqs);
				const deltaGb = cachedBytes / (1024 * 1024 * 1024);
				const writeTask = async () => {
					try {
						await env.DB.prepare("UPDATE users SET used_gb = used_gb + ?, lifetime_used_gb = lifetime_used_gb + ?, used_req = used_req + ? WHERE username = ?").bind(deltaGb, deltaGb, cachedReqs, uname).run();
					} catch (e) {
						console.error(e.message);
						GLOBAL_TRAFFIC_CACHE.set(uname, (GLOBAL_TRAFFIC_CACHE.get(uname) || 0) + cachedBytes);
						USER_REQ_CACHE.set(uname, (USER_REQ_CACHE.get(uname) || 0) + cachedReqs);
					} finally {
						GLOBAL_WRITE_LOCK.delete(uname);
						GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
					}
				};
				if (ctx) {
					ctx.waitUntil(writeTask());
				} else {
					writeTask();
				}
			} else {
				GLOBAL_LAST_ACTIVE_WRITE.delete(uname);
			}
		} else {
			ACTIVE_CONNECTIONS_COUNT.set(uname, activeCount);
		}
	};
	let heartbeat;
	const runHeartbeat = async () => {
		if (serverSock.readyState === WebSocket.OPEN) {
			try {
				serverSock.send(new Uint8Array(0));
				if (!validUUID || !username) {
					heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
					return;
				}
				const nowTime = Date.now();
				const lastCheck = GLOBAL_LAST_ACTIVE_WRITE.get(username + "_hb") || 0;
				if (nowTime - lastCheck >= 20000) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username + "_hb", nowTime);

					const user = await env.DB.prepare("SELECT is_active, limit_gb, used_gb, limit_req, used_req, expiry_days, created_at, ip_limit, active_ips FROM users WHERE uuid = ?").bind(validUUID).first();
					let isExpired = false;
					let isIpLimitExpired = false;
					let updatedActiveIps = null;
					if (!user || user.is_active === 0) {
						isExpired = true;
					} else {
						if (user.limit_gb && user.used_gb >= user.limit_gb) isExpired = true;
						if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) >= user.limit_req) isExpired = true;
						if (user.expiry_days && user.created_at) {
							const expiryDate = new Date(new Date(user.created_at).getTime() + user.expiry_days * 86400000);
							if (nowTime > expiryDate.getTime()) isExpired = true;
						}
						if (!isExpired && clientIP && clientIP !== "unknown") {
							let activeIps = {};
							try { activeIps = JSON.parse(user.active_ips || "{}"); } catch (e) {}
							let hasChanges = false;
							for (const [ip, data] of Object.entries(activeIps)) {
								const lastSeen = data && typeof data === "object" ? data.timestamp : data;
								if (nowTime - lastSeen > 20000) { delete activeIps[ip]; hasChanges = true; }
							}
							if (!activeIps[clientIP]) {
								isIpLimitExpired = true;
							} else {
								const sortedIps = Object.keys(activeIps).sort((a, b) => {
									const tA = typeof activeIps[a] === "object" ? activeIps[a].timestamp : activeIps[a];
									const tB = typeof activeIps[b] === "object" ? activeIps[b].timestamp : activeIps[b];
									return tB - tA;
								});
								if (user.ip_limit && user.ip_limit > 0 && sortedIps.indexOf(clientIP) >= user.ip_limit) isIpLimitExpired = true;
							}
							if (hasChanges || isIpLimitExpired) updatedActiveIps = JSON.stringify(activeIps);
						}
					}
					if (isExpired) {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(validUUID).run();
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (isIpLimitExpired) {
						clearTimeout(heartbeat);
						closeSocketQuietly(serverSock);
						return;
					}
					if (updatedActiveIps !== null) {
						await env.DB.prepare("UPDATE users SET last_active = ?, active_ips = ? WHERE username = ?").bind(nowTime, updatedActiveIps, username).run();
					} else {
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(nowTime, username).run();
					}
				}
			} catch (e) {}
			heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
		} else {
			clearTimeout(heartbeat);
		}
	};
	heartbeat = setTimeout(runHeartbeat, Math.floor(Math.random() * 5000) + 20000);
	let remoteConnWrapper = { socket: null, connectingPromise: null, retryConnect: null };
	let reqUUID = null;
	let isTrojan = false;
	let isHeaderParsed = false;
	let isHeaderParsing = false;
	let isDnsQuery = false;
	let chunkBuffer = new Uint8Array(0);
	let uncountedBytes = 0;
	const proxyIP = storedData?.proxy_ip || "";
	let wsChain = Promise.resolve();
	let wsStopped = false,
		wsFailed = false,
		wsFinished = false;
	let wsQueueBytes = 0,
		wsQueueItems = 0;
	let currentSocketWriter = null,
		activeRemoteWriter = null;
	const releaseRemoteWriter = () => {
		if (activeRemoteWriter) {
			try {
				activeRemoteWriter.releaseLock();
			} catch (e) {}
			activeRemoteWriter = null;
		}
		currentSocketWriter = null;
	};
	const getRemoteWriter = () => {
		const s = remoteConnWrapper.socket;
		if (!s) return null;
		if (s !== currentSocketWriter) {
			releaseRemoteWriter();
			currentSocketWriter = s;
			activeRemoteWriter = s.writable.getWriter();
		}
		return activeRemoteWriter;
	};
	const upstreamQueue = createUpstreamQueue({
		getWriter: getRemoteWriter,
		releaseWriter: releaseRemoteWriter,
		retryConnect: async () => {
			if (typeof remoteConnWrapper.retryConnect === "function") {
				await remoteConnWrapper.retryConnect();
			}
		},
		closeConnection: () => {
			try {
				remoteConnWrapper.socket?.close();
			} catch (e) {}
			closeSocketQuietly(serverSock);
		},
		name: "vIeesWSQueue",
	});
	const writeToRemote = async (chunk, allowRetry = true) => {
		return upstreamQueue.writeAndAwait(chunk, allowRetry);
	};
	const processWsMessage = async (chunk) => {
		const bytes = chunk.byteLength || 0;
		await addBytes(bytes);
		if (isDnsQuery) {
			if (isTrojan) {
				await forwardTrojanUDP(chunk, serverSock, addBytes, targetDoh);
			} else {
				await forwardvIeesUDP(chunk, serverSock, null, addBytes, targetDns);
			}
			return;
		}
		if (await writeToRemote(chunk)) return;
		if (!isHeaderParsed) {
			chunkBuffer = concatBytes(chunkBuffer, chunk);
			if (chunkBuffer.byteLength < 24) return;
			
			// Detect Trojan by its fixed header: SHA-224 hex (56 ASCII bytes)
			// followed by CRLF. A real VLESS header has no CRLF at byte 56/57.
			let isTrojanCandidate = false;
			if (chunkBuffer.byteLength >= 58 && chunkBuffer[56] === 0x0d && chunkBuffer[57] === 0x0a) {
				try {
					const checkHex = new TextDecoder().decode(chunkBuffer.slice(0, 56)).toLowerCase();
					if (/^[0-9a-f]{56}$/.test(checkHex)) {
						isTrojanCandidate = true;
					}
				} catch (e) {}
			}
			if (isTrojanCandidate || isTrojan) {
				isTrojan = true;
			}
			if (isTrojan) {
				// Trojan header: [SHA224 hex (56)][CRLF(2)][CMD(1)][ADDR_TYPE(1)][addr][port(2)][CRLF(2)]
				// NOTE: Trojan ADDR_TYPE differs from VLESS: 1=IPv4, 3=domain, 4=IPv6.
				if (chunkBuffer.byteLength < 60) return;
				const tAtyp = chunkBuffer[59];
				if (tAtyp === 1) {
					if (chunkBuffer.byteLength < 68) return;
				} else if (tAtyp === 3) {
					if (chunkBuffer.byteLength < 61) return;
					if (chunkBuffer.byteLength < 61 + chunkBuffer[60] + 4) return;
				} else if (tAtyp === 4) {
					if (chunkBuffer.byteLength < 80) return;
				} else {
					return; // invalid
				}
			} else {
				let optLen = chunkBuffer[17];
				let requiredLen = 18 + optLen + 4; 
				if (chunkBuffer.byteLength < requiredLen) return;
				
				let addrType = chunkBuffer[18 + optLen + 3];
				if (addrType === 1) {
					requiredLen += 4;
				} else if (addrType === 2) {
					requiredLen += 1;
					if (chunkBuffer.byteLength < requiredLen) return;
					requiredLen += chunkBuffer[18 + optLen + 4];
				} else if (addrType === 3) {
					requiredLen += 16;
				}
				
				if (chunkBuffer.byteLength < requiredLen) return;
			}

			if (isHeaderParsing) return;
			isHeaderParsing = true;
			if (isTrojan) {
				const shaHex = new TextDecoder().decode(chunkBuffer.subarray(0, 56)).toLowerCase();
				reqUUID = await findUUIDFromTrojanHash(env, shaHex);
			} else {
				reqUUID = extractUUIDFromvIees(chunkBuffer);
			}
			if (!reqUUID) {
				serverSock.close();
				return;
			}
			let user = null;
			try {
				user = await env.DB.prepare("SELECT * FROM users WHERE uuid = ?").bind(reqUUID).first();
			} catch (e) {}
			if (!user) {
				serverSock.close();
				return;
			}
			username = user.username;
			validUUID = reqUUID;
			let currentReqs = USER_REQ_CACHE.get(username) || 0;
			USER_REQ_CACHE.set(username, currentReqs + 1);
			if (!GLOBAL_TRAFFIC_CACHE.has(username)) {
				GLOBAL_TRAFFIC_CACHE.set(username, 0);
			}
			if (isOfflineSet || serverSock.readyState !== WebSocket.OPEN) {
				return;
			}
			if (user.is_active === 0) {
				serverSock.close();
				return;
			}
			if (user.limit_gb && user.used_gb >= user.limit_gb) {
				serverSock.close();
				return;
			}
			if (user.limit_req && user.used_req + (USER_REQ_CACHE.get(username) || 0) > user.limit_req) {
				serverSock.close();
				return;
			}
			if (user.expiry_days && user.created_at) {
				const created = new Date(user.created_at);
				const expiryDate = new Date(created.getTime() + user.expiry_days * 24 * 60 * 60 * 1000);
				if (new Date() > expiryDate) {
					try {
						await env.DB.prepare("UPDATE users SET is_active = 0, last_active = 0 WHERE uuid = ?").bind(reqUUID).run();
					} catch (e) {}
					serverSock.close();
					return;
				}
			}
			if (user.block_porn === 1 && user.block_ads === 1) {
				targetDns = "94.140.14.15";
				targetDoh = "https://family.adguard-dns.com/dns-query";
			} else if (user.block_porn === 1) {
				targetDns = "1.1.1.3";
				targetDoh = "https://family.cloudflare-dns.com/dns-query";
			} else if (user.block_ads === 1) {
				targetDns = "94.140.14.14";
				targetDoh = "https://dns.adguard-dns.com/dns-query";
			}
			if (clientIP && clientIP !== "unknown") {
				let activeIps = {};
				try { activeIps = JSON.parse(user.active_ips || "{}"); } catch (e) {}
				const now = Date.now();
				for (const [ip, data] of Object.entries(activeIps)) {
					const lastSeen = data && typeof data === "object" ? data.timestamp : data;
					if (now - lastSeen > 20000) delete activeIps[ip];
				}
				let isNewIp = false;
				if (!activeIps[clientIP]) {
					const sortedIps = Object.keys(activeIps);
					if (user.ip_limit && user.ip_limit > 0 && sortedIps.length >= user.ip_limit) {
						serverSock.close();
						return;
					}
					activeIps[clientIP] = { timestamp: now, count: 1 };
					isNewIp = true;
				} else {
					if (typeof activeIps[clientIP] === "object") {
						activeIps[clientIP].timestamp = now;
						activeIps[clientIP].count = (activeIps[clientIP].count || 0) + 1;
					} else {
						activeIps[clientIP] = { timestamp: now, count: 1 };
					}
				}
				const lastWrite = GLOBAL_LAST_ACTIVE_WRITE.get(username) || 0;
				if (isNewIp || (now - lastWrite > 10000)) {
					GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
					const updateTask = async () => {
						try {
							await env.DB.prepare("UPDATE users SET active_ips = ?, last_active = ? WHERE uuid = ?").bind(JSON.stringify(activeIps), now, reqUUID).run();
						} catch (e) {}
					};
					if (ctx) ctx.waitUntil(updateTask());
					else updateTask();
				}
			}
			isHeaderParsed = true;
			let activeCount = ACTIVE_CONNECTIONS_COUNT.get(username) || 0;
			ACTIVE_CONNECTIONS_COUNT.set(username, activeCount + 1);
			hasCountedAsActive = true;
			if (activeCount === 0) {
				const setOnlineTask = async () => {
					try {
						const now = Date.now();
						GLOBAL_LAST_ACTIVE_WRITE.set(username, now);
						await env.DB.prepare("UPDATE users SET last_active = ? WHERE username = ?").bind(now, username).run();
					} catch (e) {}
				};
				if (ctx) ctx.waitUntil(setOnlineTask());
				else setOnlineTask();
			}
			try {
				let offset, cmd, port, addrType;
				if (isTrojan) {
					offset = 58;
					cmd = chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
				} else {
					offset = 17;
					const optLen = chunkBuffer[offset++];
					offset += optLen;
					cmd = chunkBuffer[offset++];
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					addrType = chunkBuffer[offset++];
				}
				let addr = "";
				if (addrType === 1) {
					addr = `${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}.${chunkBuffer[offset++]}`;
				} else if (isTrojan ? addrType === 3 : addrType === 2) {
					const domainLen = chunkBuffer[offset++];
					addr = new TextDecoder().decode(chunkBuffer.slice(offset, offset + domainLen));
					offset += domainLen;
				} else if (isTrojan ? addrType === 4 : addrType === 3) {
					const v6 = [];
					for (let i = 0; i < 8; i++) {
						v6.push(((chunkBuffer[offset++] << 8) | chunkBuffer[offset++]).toString(16));
					}
					addr = v6.join(":");
				} else {
					serverSock.close();
					return;
				}
				if (isTrojan) {
					port = (chunkBuffer[offset++] << 8) | chunkBuffer[offset++];
					offset += 2;
				}
				const rawData = chunkBuffer.slice(offset);
				const respHeader = isTrojan ? null : new Uint8Array([chunkBuffer[0], 0]);
				if ((user.block_ads === 1 || user.block_porn === 1) && (isTrojan ? addrType === 3 : addrType === 2) && port !== 53) {
					try {
						const dnsCheck = await dohQuery(addr, "A", targetDoh);
						const isBlocked = dnsCheck.some((r) => r.data === "0.0.0.0" || r.data === "::" || r.data === "176.103.130.130");
						if (isBlocked) {
							serverSock.close();
							return;
						}
						const validIps = dnsCheck.filter((r) => r.type === 1 && typeof r.data === "string" && isIPv4(r.data));
						if (validIps.length > 0) {
							addr = validIps[0].data;
						}
					} catch (e) {}
				}
				if (cmd === 2 || (isTrojan && cmd === 3)) {
					if (port === 53) {
						isDnsQuery = true;
						if (isTrojan) {
							await forwardTrojanUDP(rawData, serverSock, addBytes, targetDoh);
						} else {
							await forwardvIeesUDP(rawData, serverSock, respHeader, addBytes, targetDns);
						}
					} else {
						serverSock.close();
					}
					return;
				}
				if (port === 25 || port === 22 || /^(127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|::1|fd[0-9a-f]{2}:|fe80:)/i.test(addr)) {
					serverSock.close();
					return;
				}
				const connectTCP = async (dataPayload = null, useFallback = true) => {
					if (remoteConnWrapper.connectingPromise) {
						await remoteConnWrapper.connectingPromise;
						return;
					}
					const task = (async () => {
							let s = null;
							const socks5 = user?.user_socks5 || "";
							if (socks5) {
								try {
									let targetAddr = addr;
									
									if (addrType === 2) {
										// تلاش اول: استفاده از API مطمئن کلودفلر برای گرفتن IPv4
										try {
											const cfDns = await fetch("https://cloudflare-dns.com/dns-query?name=" + addr + "&type=A", {
												headers: { "Accept": "application/dns-json" }
											});
											const cfJson = await cfDns.json();
											if (cfJson.Status === 0 && cfJson.Answer) {
												const v4 = cfJson.Answer.find(a => a.type === 1 && isIPv4(a.data));
												if (v4) targetAddr = v4.data;
											}
										} catch (e) {
											// تلاش دوم: استفاده از تابع DNS محلی
											try {
												const dnsCheck = await dohQuery(addr, "A", targetDoh);
												const validIps = dnsCheck.filter(r => r.type === 1 && typeof r.data === "string" && isIPv4(r.data));
												if (validIps.length > 0) targetAddr = validIps[0].data;
											} catch (e2) {}
										}
									} else if (addrType === 3) {
										// اگه کلاینت مستقیماً آدرس IPv6 فرستاده بود، چون پروکسیِ ما IPv6 نداره هنگ میکنه.
										// پس همون اول کانکشن رو قطع میکنیم تا مرورگر درجا روی IPv4 تلاش مجدد (Fallback) کنه.
										serverSock.close();
										return;
									}
									
									s = await connectProxy(socks5, targetAddr, port, dataPayload);
								} catch (proxyErr) {
									if (user.auto_rotate_user_proxy === 1) {
										const replaceTask = replaceBrokenProxy(user.username, env, socks5);
										if (ctx) ctx.waitUntil(replaceTask);
										else replaceTask.catch(() => {});
									}
									throw proxyErr;
								}
							} else {
							let activeProxyIP = proxyIP;
							let tryProxyFirst = false;
							if (user?.user_proxy_ip) {
								activeProxyIP = user.user_proxy_ip;
								tryProxyFirst = true;
							}
							let fHost = activeProxyIP;
							let fPort = port;
							if (activeProxyIP) {
								if (activeProxyIP.startsWith("[")) {
									const closeIdx = activeProxyIP.indexOf("]");
									if (closeIdx !== -1) {
										fHost = activeProxyIP.substring(1, closeIdx);
										if (activeProxyIP.length > closeIdx + 1 && activeProxyIP[closeIdx + 1] === ":") {
											fPort = parseInt(activeProxyIP.substring(closeIdx + 2)) || port;
										}
									}
								} else {
									const lastColon = activeProxyIP.lastIndexOf(":");
									if (lastColon !== -1 && activeProxyIP.indexOf(":") === lastColon) {
										fHost = activeProxyIP.substring(0, lastColon);
										fPort = parseInt(activeProxyIP.substring(lastColon + 1)) || port;
									} else {
										fHost = activeProxyIP;
									}
								}
							}
							const isCustomProxy = tryProxyFirst && activeProxyIP && activeProxyIP !== "";
							if (isCustomProxy) {
								try {
									s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
								} catch (err) {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								}
							} else {
								try {
									s = await connectDirect(addr, port, dataPayload, targetDoh);
								} catch (err) {
									if (useFallback && activeProxyIP) {
										s = await connectDirect(fHost, fPort, dataPayload, targetDoh);
									} else {
										throw err;
									}
								}
							}
						}
						remoteConnWrapper.socket = s;
						s.closed.catch(() => {}).finally(() => closeSocketQuietly(serverSock));
						connectStreams(s, serverSock, respHeader, null, (b) => {
							addBytes(b);
						});
					})();
					remoteConnWrapper.connectingPromise = task;
					try {
						await task;
					} finally {
						if (remoteConnWrapper.connectingPromise === task) {
							remoteConnWrapper.connectingPromise = null;
						}
					}
				};
				remoteConnWrapper.retryConnect = async () => connectTCP(null, false);
				await connectTCP(rawData, true);
			} catch (e) {
				serverSock.close();
			}
		}
	};
	const handleWsError = (err) => {
		if (wsFailed) return;
		wsFailed = true;
		wsStopped = true;
		wsQueueBytes = 0;
		wsQueueItems = 0;
		upstreamQueue.clear();
		releaseRemoteWriter();
		closeSocketQuietly(serverSock);
		setOffline();
	};
	const pushToChain = (task) => {
		wsChain = wsChain.then(task).catch(handleWsError);
	};
	serverSock.addEventListener("message", (event) => {
		if (wsStopped || wsFailed) return;
		const size = event.data.byteLength || 0;
		const nextBytes = wsQueueBytes + size;
		const nextItems = wsQueueItems + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			handleWsError(new Error("ws queue overflow"));
			return;
		}
		wsQueueBytes = nextBytes;
		wsQueueItems = nextItems;
		pushToChain(async () => {
			wsQueueBytes = Math.max(0, wsQueueBytes - size);
			wsQueueItems = Math.max(0, wsQueueItems - 1);
			if (wsFailed) return;
			await processWsMessage(event.data);
		});
	});
	serverSock.addEventListener("close", () => {
		clearTimeout(heartbeat);
		closeSocketQuietly(serverSock);
		setOffline();
		if (wsFinished) return;
		wsFinished = true;
		wsStopped = true;
		pushToChain(async () => {
			if (wsFailed) return;
			await upstreamQueue.awaitEmpty();
			releaseRemoteWriter();
		});
	});
	serverSock.addEventListener("error", (err) => {
		handleWsError(err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}
async function getCfUsage(env) {
	if (!env.CF_API_TOKEN || !env.CF_ACCOUNT_ID) return { today: 0, total: 0 };
	try {
		const now = new Date();
		const startOfDay = new Date(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()).toISOString();
		const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000).toISOString();
		const q = `query {
      viewer {
        accounts(filter: {accountTag: "${env.CF_ACCOUNT_ID}"}) {
          today: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${startOfDay}"}) {
            sum { requests }
          }
          total: workersInvocationsAdaptive(limit: 10, filter: {datetime_geq: "${thirtyDaysAgo}"}) {
            sum { requests }
          }
        }
      }
    }`;
		const res = await fetch("https://api.cloudflare.com/client/v4/graphql", {
			method: "POST",
			headers: { Authorization: "Bearer " + env.CF_API_TOKEN, "Content-Type": "application/json" },
			body: JSON.stringify({ query: q }),
		});
		const j = await res.json();
		const acc = j?.data?.viewer?.accounts?.[0];
		const todayReqs = acc?.today?.[0]?.sum?.requests || 0;
		const totalReqs = acc?.total?.[0]?.sum?.requests || todayReqs;
		return { today: todayReqs, total: totalReqs };
	} catch (e) {
		return { today: 0, total: 0 };
	}
}
function isIPv4(value) {
	const parts = String(value || "").split(".");
	return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function stripIPv6Brackets(hostname = "") {
	const host = String(hostname || "").trim();
	return host.startsWith("[") && host.endsWith("]") ? host.slice(1, -1) : host;
}
function isIPHostname(hostname = "") {
	const host = stripIPv6Brackets(hostname);
	if (isIPv4(host)) return true;
	if (!host.includes(":")) return false;
	try {
		new URL(`http://[${host}]/`);
		return true;
	} catch (e) {
		return false;
	}
}
function convertToUint8Array(data) {
	if (data instanceof Uint8Array) return data;
	if (data instanceof ArrayBuffer) return new Uint8Array(data);
	if (ArrayBuffer.isView(data)) return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
	return new Uint8Array(data || 0);
}
function concatBytes(...chunkList) {
	const chunks = chunkList.map(convertToUint8Array);
	const total = chunks.reduce((sum, c) => sum + c.byteLength, 0);
	const result = new Uint8Array(total);
	let offset = 0;
	for (const c of chunks) {
		result.set(c, offset);
		offset += c.byteLength;
	}
	return result;
}
function closeSocketQuietly(socket) {
	try {
		if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
			socket.close();
		}
	} catch (e) {}
}
async function dohQuery(domain, recordType, targetDoh = DOH_RESOLVER) {
	const cacheKey = `${domain}:${recordType}:${targetDoh}`;
	if (DNS_CACHE.has(cacheKey)) {
		const cached = DNS_CACHE.get(cacheKey);
		if (Date.now() < cached.expires) return cached.data;
		DNS_CACHE.delete(cacheKey);
	}
	try {
		const typeMap = { A: 1, AAAA: 28 };
		const qtype = typeMap[recordType.toUpperCase()] || 1;
		const encodeDomain = (name) => {
			const parts = name.endsWith(".") ? name.slice(0, -1).split(".") : name.split(".");
			const bufs = [];
			for (const label of parts) {
				const enc = new TextEncoder().encode(label);
				bufs.push(new Uint8Array([enc.length]), enc);
			}
			bufs.push(new Uint8Array([0]));
			return concatBytes(...bufs);
		};
		const qname = encodeDomain(domain);
		const query = new Uint8Array(12 + qname.length + 4);
		const qview = new DataView(query.buffer);
		qview.setUint16(0, crypto.getRandomValues(new Uint16Array(1))[0]);
		qview.setUint16(2, 0x0100);
		qview.setUint16(4, 1);
		query.set(qname, 12);
		qview.setUint16(12 + qname.length, qtype);
		qview.setUint16(12 + qname.length + 2, 1);
		const response = await fetch(targetDoh, {
			method: "POST",
			headers: {
				"Content-Type": "application/dns-message",
				Accept: "application/dns-message",
			},
			body: query,
		});
		if (!response.ok) return [];
		const buf = new Uint8Array(await response.arrayBuffer());
		const dv = new DataView(buf.buffer);
		const qdcount = dv.getUint16(4);
		const ancount = dv.getUint16(6);
		const parseName = (pos) => {
			const labels = [];
			let p = pos,
				jumped = false,
				endPos = -1,
				safe = 128;
			while (p < buf.length && safe-- > 0) {
				const len = buf[p];
				if (len === 0) {
					if (!jumped) endPos = p + 1;
					break;
				}
				if ((len & 0xc0) === 0xc0) {
					if (!jumped) endPos = p + 2;
					p = ((len & 0x3f) << 8) | buf[p + 1];
					jumped = true;
					continue;
				}
				labels.push(new TextDecoder().decode(buf.slice(p + 1, p + 1 + len)));
				p += len + 1;
			}
			if (endPos === -1) endPos = p + 1;
			return [labels.join("."), endPos];
		};
		let offset = 12;
		for (let i = 0; i < qdcount; i++) {
			const [, end] = parseName(offset);
			offset = Number(end) + 4;
		}
		const answers = [];
		for (let i = 0; i < ancount && offset < buf.length; i++) {
			const [name, nameEnd] = parseName(offset);
			offset = Number(nameEnd);
			const type = dv.getUint16(offset);
			offset += 2;
			offset += 2;
			const ttl = dv.getUint32(offset);
			offset += 4;
			const rdlen = dv.getUint16(offset);
			offset += 2;
			const rdata = buf.slice(offset, offset + rdlen);
			offset += rdlen;
			let data;
			if (type === 1 && rdlen === 4) {
				data = `${rdata[0]}.${rdata[1]}.${rdata[2]}.${rdata[3]}`;
			} else if (type === 28 && rdlen === 16) {
				const segs = [];
				for (let j = 0; j < 16; j += 2) segs.push(((rdata[j] << 8) | rdata[j + 1]).toString(16));
				data = segs.join(":");
			} else {
				data = Array.from(rdata)
					.map((b) => b.toString(16).padStart(2, "0"))
					.join("");
			}
			answers.push({ name, type, TTL: ttl, data });
		}
		DNS_CACHE.set(cacheKey, { data: answers, expires: Date.now() + DNS_CACHE_TTL });
		return answers;
	} catch (e) {
		return [];
	}
}
function createUpstreamQueue({ getWriter, releaseWriter, retryConnect, closeConnection, name = "UpstreamQueue" }) {
	let chunks = [];
	let head = 0;
	let queuedBytes = 0;
	let draining = false;
	let closed = false;
	let bundleBuffer = null;
	let idleResolvers = [];
	let activeCompletions = null;
	const settleCompletions = (completions, err = null) => {
		if (!completions) return;
		for (const comp of completions) {
			if (comp) {
				if (err) comp.reject(err);
				else comp.resolve();
			}
		}
	};
	const rejectQueued = (err) => {
		for (let i = head; i < chunks.length; i++) {
			const item = chunks[i];
			if (item && item.completions) settleCompletions(item.completions, err);
		}
	};
	const compact = () => {
		if (head > 32 && head * 2 >= chunks.length) {
			chunks = chunks.slice(head);
			head = 0;
		}
	};
	const resolveIdle = () => {
		if (queuedBytes || draining || !idleResolvers.length) return;
		const resolvers = idleResolvers;
		idleResolvers = [];
		for (const resolve of resolvers) resolve();
	};
	const clear = (err = null) => {
		const closeErr = err || (closed ? new Error(`${name}: queue closed`) : null);
		if (closeErr) {
			rejectQueued(closeErr);
			settleCompletions(activeCompletions, closeErr);
			activeCompletions = null;
		}
		chunks = [];
		head = 0;
		queuedBytes = 0;
		resolveIdle();
	};
	const shift = () => {
		if (head >= chunks.length) return null;
		const item = chunks[head];
		chunks[head++] = undefined;
		queuedBytes -= item.chunk.byteLength;
		compact();
		return item;
	};
	const bundle = () => {
		const first = shift();
		if (!first) return null;
		if (head >= chunks.length || first.chunk.byteLength >= UPSTREAM_BUNDLE_TARGET_BYTES) return first;
		let byteLength = first.chunk.byteLength;
		let end = head;
		let allowRetry = first.allowRetry;
		let completions = first.completions || null;
		while (end < chunks.length) {
			const next = chunks[end];
			const nextLength = byteLength + next.chunk.byteLength;
			if (nextLength > UPSTREAM_BUNDLE_TARGET_BYTES) break;
			byteLength = nextLength;
			allowRetry = allowRetry && next.allowRetry;
			if (next.completions) completions = completions ? completions.concat(next.completions) : next.completions;
			end++;
		}
		if (end === head) return first;
		const output = (bundleBuffer ||= new Uint8Array(UPSTREAM_BUNDLE_TARGET_BYTES));
		output.set(first.chunk);
		let offset = first.chunk.byteLength;
		while (head < end) {
			const next = chunks[head];
			chunks[head++] = undefined;
			queuedBytes -= next.chunk.byteLength;
			output.set(next.chunk, offset);
			offset += next.chunk.byteLength;
		}
		compact();
		return { chunk: output.subarray(0, byteLength), allowRetry, completions };
	};
	const drain = async () => {
		if (draining || closed) return;
		draining = true;
		try {
			let batchCount = 0;
			for (;;) {
				if (closed) break;
				const item = bundle();
				if (!item) break;
				let writer = getWriter();
				if (!writer) throw new Error(`${name}: remote writer unavailable`);
				const completions = item.completions || null;
				activeCompletions = completions;
				try {
					try {
						await writer.write(item.chunk);
					} catch (err) {
						releaseWriter?.();
						if (!item.allowRetry || typeof retryConnect !== "function") throw err;
						await retryConnect();
						writer = getWriter();
						if (!writer) throw err;
						await writer.write(item.chunk);
					}
					settleCompletions(completions);
				} catch (err) {
					settleCompletions(completions, err);
					throw err;
				} finally {
					if (activeCompletions === completions) activeCompletions = null;
				}
				batchCount++;
				if (batchCount >= 16) {
					await new Promise((resolve) => setTimeout(resolve, 0));
					batchCount = 0;
				}
			}
		} catch (err) {
			closed = true;
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
		} finally {
			draining = false;
			if (!closed && head < chunks.length) setTimeout(drain, 0);
			else resolveIdle();
		}
	};
	const enqueue = (data, allowRetry = true, waitForFlush = false) => {
		if (closed) return false;
		if (!getWriter()) return false;
		const chunk = convertToUint8Array(data);
		if (!chunk.byteLength) return true;
		const nextBytes = queuedBytes + chunk.byteLength;
		const nextItems = chunks.length - head + 1;
		if (nextBytes > UPSTREAM_QUEUE_MAX_BYTES || nextItems > UPSTREAM_QUEUE_MAX_ITEMS) {
			closed = true;
			const err = Object.assign(new Error(`${name}: upload queue overflow (${nextBytes}B/${nextItems})`), { isQueueOverflow: true });
			clear(err);
			try {
				closeConnection?.(err);
			} catch (_) {}
			throw err;
		}
		let completionPromise = null;
		let completions = null;
		if (waitForFlush) {
			completions = [];
			completionPromise = new Promise((resolve, reject) => completions.push({ resolve, reject }));
		}
		chunks.push({ chunk, allowRetry, completions });
		queuedBytes = nextBytes;
		if (!draining) setTimeout(drain, 0);
		return waitForFlush ? completionPromise.then(() => true) : true;
	};
	return {
		writeAndAwait(data, allowRetry = true) {
			return enqueue(data, allowRetry, true);
		},
		async awaitEmpty() {
			if (!queuedBytes && !draining) return;
			await new Promise((resolve) => idleResolvers.push(resolve));
		},
		clear() {
			closed = true;
			clear();
		},
	};
}
function createDownstreamSender(webSocket, headerData = null) {
	const packetCap = DOWNSTREAM_GRAIN_BYTES;
	const tailBytes = DOWNSTREAM_GRAIN_TAIL_THRESHOLD;
	const lowWaterBytes = Math.max(4096, tailBytes << 3);
	let header = headerData;
	let pendingBuffer = new Uint8Array(packetCap);
	let pendingBytes = 0;
	let flushTimer = null;
	let taskQueued = false;
	let generation = 0;
	let scheduledGeneration = 0;
	let waitRounds = 0;
	let flushPromise = null;
	const sendRawChunk = async (chunk) => {
		if (webSocket.readyState !== WebSocket.OPEN) throw new Error("ws.readyState is not open");
		webSocket.send(chunk);
	};
	const attachResponseHeader = (chunk) => {
		if (!header) return chunk;
		const merged = new Uint8Array(header.length + chunk.byteLength);
		merged.set(header, 0);
		merged.set(chunk, header.length);
		header = null;
		return merged;
	};
	const flush = async () => {
		while (flushPromise) await flushPromise;
		if (flushTimer) clearTimeout(flushTimer);
		flushTimer = null;
		taskQueued = false;
		if (!pendingBytes) return;
		const output = pendingBuffer.subarray(0, pendingBytes).slice();
		pendingBuffer = new Uint8Array(packetCap);
		pendingBytes = 0;
		waitRounds = 0;
		flushPromise = sendRawChunk(output).finally(() => {
			flushPromise = null;
		});
		return flushPromise;
	};
	const scheduleFlush = () => {
		if (flushTimer || taskQueued) return;
		taskQueued = true;
		scheduledGeneration = generation;
		setTimeout(() => {
			taskQueued = false;
			if (!pendingBytes || flushTimer) return;
			if (packetCap - pendingBytes < tailBytes) {
				flush().catch(() => closeSocketQuietly(webSocket));
				return;
			}
			flushTimer = setTimeout(
				() => {
					flushTimer = null;
					if (!pendingBytes) return;
					if (packetCap - pendingBytes < tailBytes) {
						flush().catch(() => closeSocketQuietly(webSocket));
						return;
					}
					if (waitRounds < 2 && (generation !== scheduledGeneration || pendingBytes < lowWaterBytes)) {
						waitRounds++;
						scheduledGeneration = generation;
						scheduleFlush();
						return;
					}
					flush().catch(() => closeSocketQuietly(webSocket));
				},
				Math.max(DOWNSTREAM_GRAIN_SILENT_MS, 1),
			);
		}, 0);
	};
	return {
		async sendDirect(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			await sendRawChunk(chunk);
		},
		async send(data) {
			let chunk = convertToUint8Array(data);
			if (!chunk.byteLength) return;
			chunk = attachResponseHeader(chunk);
			let offset = 0;
			const totalBytes = chunk.byteLength;
			while (offset < totalBytes) {
				if (!pendingBytes && totalBytes - offset >= packetCap) {
					const sendBytes = Math.min(packetCap, totalBytes - offset);
					const view = offset || sendBytes !== totalBytes ? chunk.subarray(offset, offset + sendBytes) : chunk;
					await sendRawChunk(view);
					offset += sendBytes;
					continue;
				}
				const copyBytes = Math.min(packetCap - pendingBytes, totalBytes - offset);
				pendingBuffer.set(chunk.subarray(offset, offset + copyBytes), pendingBytes);
				pendingBytes += copyBytes;
				offset += copyBytes;
				generation++;
				if (pendingBytes === packetCap || packetCap - pendingBytes < tailBytes) await flush();
				else scheduleFlush();
			}
		},
		flush,
	};
}
async function waitForBackpressure(ws) {
	if (typeof ws.bufferedAmount === "number") {
		let maxAttempts = 150;
		while (ws.bufferedAmount > 1024 * 1024 && maxAttempts > 0) {
			if (ws.readyState !== WebSocket.OPEN) break;
			await new Promise((r) => setTimeout(r, 20));
			maxAttempts--;
		}
	}
}
async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, onBytes) {
	let header = headerData,
		hasData = false,
		reader,
		useBYOB = false;
	const BYOB_LIMIT = 64 * 1024;
	const downstreamSender = createDownstreamSender(webSocket, header);
	header = null;
	try {
		reader = remoteSocket.readable.getReader({ mode: "byob" });
		useBYOB = true;
	} catch (e) {
		reader = remoteSocket.readable.getReader();
	}
	try {
		if (!useBYOB) {
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read();
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				await downstreamSender.send(value);
			}
		} else {
			let readBuffer = new ArrayBuffer(BYOB_LIMIT);
			while (true) {
				await waitForBackpressure(webSocket);
				const { done, value } = await reader.read(new Uint8Array(readBuffer, 0, BYOB_LIMIT));
				if (done) break;
				if (!value || value.byteLength === 0) continue;
				hasData = true;
				if (typeof onBytes === "function") onBytes(value.byteLength);
				if (value.byteLength >= DOWNSTREAM_GRAIN_BYTES) {
					await downstreamSender.flush();
					await downstreamSender.sendDirect(value);
					readBuffer = new ArrayBuffer(BYOB_LIMIT);
				} else {
					await downstreamSender.send(value);
					readBuffer = value.buffer.byteLength >= BYOB_LIMIT ? value.buffer : new ArrayBuffer(BYOB_LIMIT);
				}
			}
		}
		await downstreamSender.flush();
	} catch (err) {
		closeSocketQuietly(webSocket);
	} finally {
		try {
			reader.cancel();
		} catch (e) {}
		try {
			reader.releaseLock();
		} catch (e) {}
	}
	if (!hasData && retryFunc) await retryFunc();
}
async function connectDirect(targetHost, targetPort, initialData, targetDoh) {
	let socket = null;
	try {
		socket = connect({ hostname: targetHost, port: targetPort });
		const writer = socket.writable.getWriter();
		if (initialData && initialData.byteLength > 0) {
			await writer.write(initialData);
		}
		writer.releaseLock();
		return socket;
	} catch (e) {
		if (socket) {
			try {
				await socket.close();
			} catch (err) {}
		}
		throw new Error(`Connection failed to ${targetHost}:${targetPort}`);
	}
}
async function forwardTrojanUDP(udpChunk, webSocket, onBytes, targetDoh) {
	try {
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 7) return;
		let offset = 0;
		const addrType = data[offset++];
		let headerAddrBytes = [];
		if (addrType === 1) {
			if (data.byteLength < offset + 4) return;
			headerAddrBytes = [addrType, data[offset], data[offset + 1], data[offset + 2], data[offset + 3]];
			offset += 4;
		} else if (addrType === 3) {
			if (data.byteLength < offset + 1) return;
			const domainLen = data[offset++];
			if (data.byteLength < offset + domainLen) return;
			headerAddrBytes = [addrType, domainLen, ...data.slice(offset, offset + domainLen)];
			offset += domainLen;
		} else if (addrType === 4) {
			if (data.byteLength < offset + 16) return;
			headerAddrBytes = [addrType, ...data.slice(offset, offset + 16)];
			offset += 16;
		} else {
			return;
		}
		if (data.byteLength < offset + 4) return;
		const port = (data[offset++] << 8) | data[offset++];
		const length = (data[offset++] << 8) | data[offset++];
		offset += 2;
		if (data.byteLength < offset + length) return;
		const dnsPayload = data.slice(offset, offset + length);
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return;
		const resLen = rawResponse.byteLength;
		const udpHeader = new Uint8Array(headerAddrBytes.length + 2 + 2 + 2);
		let hOff = 0;
		for (let b of headerAddrBytes) udpHeader[hOff++] = b;
		udpHeader[hOff++] = (port >> 8) & 0xff;
		udpHeader[hOff++] = port & 0xff;
		udpHeader[hOff++] = (resLen >> 8) & 0xff;
		udpHeader[hOff++] = resLen & 0xff;
		udpHeader[hOff++] = 0x0D;
		udpHeader[hOff++] = 0x0A;
		const merged = new Uint8Array(udpHeader.length + resLen);
		merged.set(udpHeader, 0);
		merged.set(rawResponse, udpHeader.length);
		webSocket.send(merged.buffer);
	} catch (e) { }
}
async function forwardvIeesUDP(udpChunk, webSocket, respHeader, onBytes, dnsServer = "8.8.4.4") {
	try {
		let targetDoh = "https://cloudflare-dns.com/dns-query";
		if (dnsServer === "94.140.14.15") targetDoh = "https://family.adguard-dns.com/dns-query";
		else if (dnsServer === "1.1.1.3") targetDoh = "https://family.cloudflare-dns.com/dns-query";
		else if (dnsServer === "94.140.14.14") targetDoh = "https://dns.adguard-dns.com/dns-query";
		const data = convertToUint8Array(udpChunk);
		if (data.byteLength < 2) return false;
		const length = (data[0] << 8) | data[1];
		if (data.byteLength < 2 + length) return false;
		const dnsPayload = data.slice(2, 2 + length);
		const response = await fetch(targetDoh, {
			method: 'POST',
			headers: {
				'Accept': 'application/dns-message',
				'Content-Type': 'application/dns-message'
			},
			body: dnsPayload
		});
		if (!response.ok) return false;
		const rawResponse = new Uint8Array(await response.arrayBuffer());
		if (typeof onBytes === "function") onBytes(rawResponse.byteLength);
		if (webSocket.readyState !== WebSocket.OPEN) return false;
		const resLen = rawResponse.byteLength;
		const udpPacket = new Uint8Array(2 + resLen);
		udpPacket[0] = (resLen >> 8) & 0xff;
		udpPacket[1] = resLen & 0xff;
		udpPacket.set(rawResponse, 2);
		const header = respHeader || new Uint8Array(0);
		const merged = new Uint8Array(header.length + udpPacket.byteLength);
		merged.set(header, 0);
		merged.set(udpPacket, header.length);
		webSocket.send(merged.buffer);
		return true;
	} catch (e) {
		return false;
	}
}
function extractUUIDFromvIees(data) {
	if (data.byteLength < 17) return null;
	const hex = [...data.slice(1, 17)].map((b) => b.toString(16).padStart(2, "0")).join("");
	return `${hex.substring(0, 8)}-${hex.substring(8, 12)}-${hex.substring(12, 16)}-${hex.substring(16, 20)}-${hex.substring(20)}`;
}
function sha224Bytes(input) {
	const K = [0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2];
	let h0=0xc1059ed8, h1=0x367cd507, h2=0x3070dd17, h3=0xf70e5939, h4=0xffc00b31, h5=0x68581511, h6=0x64f98fa7, h7=0xbefa4fa4;
	const bytes = typeof input === "string" ? new TextEncoder().encode(input) : new Uint8Array(input);
	const bitLen = bytes.length * 8;
	const paddedLen = Math.ceil((bytes.length + 9) / 64) * 64;
	const padded = new Uint8Array(paddedLen);
	padded.set(bytes);
	padded[bytes.length] = 0x80;
	const dv = new DataView(padded.buffer);
	dv.setUint32(paddedLen - 8, Math.floor(bitLen / 0x100000000), false);
	dv.setUint32(paddedLen - 4, bitLen >>> 0, false);
	const w = new Int32Array(64);
	const rotr = (x, n) => (x >>> n) | (x << (32 - n));
	for (let i = 0; i < paddedLen; i += 64) {
		for (let t = 0; t < 16; t++) w[t] = dv.getInt32(i + t * 4, false);
		for (let t = 16; t < 64; t++) {
			const s0 = rotr(w[t-15], 7) ^ rotr(w[t-15], 18) ^ (w[t-15] >>> 3);
			const s1 = rotr(w[t-2], 17) ^ rotr(w[t-2], 19) ^ (w[t-2] >>> 10);
			w[t] = (w[t-16] + s0 + w[t-7] + s1) | 0;
		}
		let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
		for (let t = 0; t < 64; t++) {
			const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
			const ch = (e & f) ^ (~e & g);
			const t1 = (h + S1 + ch + K[t] + w[t]) | 0;
			const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
			const maj = (a & b) ^ (a & c) ^ (b & c);
			const t2 = (S0 + maj) | 0;
			h=g; g=f; f=e; e=(d + t1) | 0; d=c; c=b; b=a; a=(t1 + t2) | 0;
		}
		h0=(a+h0)|0; h1=(b+h1)|0; h2=(c+h2)|0; h3=(d+h3)|0; h4=(e+h4)|0; h5=(f+h5)|0; h6=(g+h6)|0; h7=(h+h7)|0;
	}
	return [h0>>>0, h1>>>0, h2>>>0, h3>>>0, h4>>>0, h5>>>0, h6>>>0].map((x) => x.toString(16).padStart(8, "0")).join("");
}
async function sha224Hex(input) {
	try {
		return sha224Bytes(input);
	} catch (e) {
		return null;
	}
}
const GLOBAL_TROJAN_HASH_CACHE = { ts: 0, map: null };
async function findUUIDFromTrojanHash(env, shaHex) {
	try {
		if (!GLOBAL_TROJAN_HASH_CACHE.map || Date.now() - GLOBAL_TROJAN_HASH_CACHE.ts > 300000) {
			const { results } = await env.DB.prepare("SELECT uuid FROM users").all();
			const map = new Map();
			for (const u of results) {
				const h = await sha224Hex(u.uuid);
				if (h && !map.has(h)) map.set(h, u.uuid);
			}
			GLOBAL_TROJAN_HASH_CACHE.map = map;
			GLOBAL_TROJAN_HASH_CACHE.ts = Date.now();
		}
		return GLOBAL_TROJAN_HASH_CACHE.map.get(shaHex) || null;
	} catch (e) {
		return null;
	}
}
function trackRequest(env, ctx) {
	GLOBAL_REQ_COUNT++;
	const now = Date.now();
	if ((now - GLOBAL_LAST_REQ_WRITE > 900000 || GLOBAL_REQ_COUNT > 5000) && GLOBAL_REQ_COUNT > 0) {
		GLOBAL_LAST_REQ_WRITE = now;
		const countToSave = GLOBAL_REQ_COUNT;
		GLOBAL_REQ_COUNT = 0;
		const task = async () => {
			try {
				const today = new Date().toISOString().split("T")[0];
				await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_total', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				const lastDateRow = await env.DB.prepare("SELECT value FROM settings WHERE key = 'req_last_date'").first();
				if (!lastDateRow || lastDateRow.value !== today) {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_last_date', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(today, today).run();
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = ?").bind(String(countToSave), String(countToSave)).run();
				} else {
					await env.DB.prepare("INSERT INTO settings (key, value) VALUES ('req_today', ?) ON CONFLICT(key) DO UPDATE SET value = CAST(value AS INTEGER) + ?").bind(String(countToSave), String(countToSave)).run();
				}
			} catch (e) {}
		};
		if (ctx) ctx.waitUntil(task());
		else task();
	}
}
async function connectProxy(proxyStr, destAddr, destPort, initialData) {
	let normalized = proxyStr;
	if (proxyStr.includes("t.me/socks") || proxyStr.includes("tg://socks")) {
		const server = proxyStr.match(/server=([^&]+)/)?.[1];
		const port = proxyStr.match(/port=([^&]+)/)?.[1];
		const user = proxyStr.match(/user=([^&]+)/)?.[1];
		const pass = proxyStr.match(/pass=([^&]+)/)?.[1];
		if (server && port) {
			normalized = user && pass ? `socks5://${user}:${pass}@${server}:${port}` : `socks5://${server}:${port}`;
		}
	}
	const isHttp = normalized.toLowerCase().startsWith("http://") || normalized.toLowerCase().startsWith("https://");
	const isSocks4 = normalized.toLowerCase().startsWith("socks4://");
	let cleanStr = normalized.replace(/^(socks4|socks5|socks|http|https):\/\//i, "");
	if (isHttp) {
		return await connectHttp(cleanStr, destAddr, destPort, initialData);
	}
	if (isSocks4) {
		return await connectSocks4(cleanStr, destAddr, destPort, initialData);
	}
	return await connectSocks5(cleanStr, destAddr, destPort, initialData);
}
async function connectSocks4(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 1080);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		const portHigh = (destPort >> 8) & 0xff;
		const portLow = destPort & 0xff;
		let req;
		if (isIPv4(destAddr)) {
			const ipBytes = destAddr.split(".").map(Number);
			req = new Uint8Array([0x04, 0x01, portHigh, portLow, ipBytes[0], ipBytes[1], ipBytes[2], ipBytes[3], 0x00]);
		} else {
			const hostBytes = new TextEncoder().encode(destAddr);
			req = new Uint8Array(9 + hostBytes.length + 1);
			req[0] = 0x04;
			req[1] = 0x01;
			req[2] = portHigh;
			req[3] = portLow;
			req[4] = 0x00;
			req[5] = 0x00;
			req[6] = 0x00;
			req[7] = 0x01;
			req[8] = 0x00;
			req.set(hostBytes, 9);
			req[9 + hostBytes.length] = 0x00;
		}
		await writer.write(req);
		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x00 || res.value[1] !== 0x5a) {
			throw new Error("پـروکـسـی SOCKS4 وصل نشد یا اتصال را رد کرد");
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}
function parseProxyConfig(proxyStr, defaultPort) {
	let user = "",
		pass = "",
		host = "",
		port = defaultPort;
	let auth = false,
		remain = proxyStr;
	if (remain.includes("@")) {
		const atIdx = remain.lastIndexOf("@");
		const authPart = remain.substring(0, atIdx);
		remain = remain.substring(atIdx + 1);
		const colonIdx = authPart.indexOf(":");
		if (colonIdx !== -1) {
			user = authPart.substring(0, colonIdx);
			pass = authPart.substring(colonIdx + 1);
		} else {
			user = authPart;
		}
		auth = true;
	}
	if (remain.startsWith("[")) {
		const closeIdx = remain.indexOf("]");
		if (closeIdx !== -1) {
			host = remain.substring(1, closeIdx);
			if (remain.length > closeIdx + 1 && remain[closeIdx + 1] === ":") port = parseInt(remain.substring(closeIdx + 2)) || defaultPort;
		}
	} else {
		const lastColon = remain.lastIndexOf(":");
		if (lastColon !== -1 && remain.indexOf(":") === lastColon) {
			host = remain.substring(0, lastColon);
			port = parseInt(remain.substring(lastColon + 1)) || defaultPort;
		} else {
			host = remain;
		}
	}
	return { user, pass, host, port, auth };
}
async function connectSocks5(socksStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(socksStr, 1080);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		if (auth) {
			await writer.write(new Uint8Array([0x05, 0x02, 0x00, 0x02]));
		} else {
			await writer.write(new Uint8Array([0x05, 0x01, 0x00]));
		}
		let res = await reader.read();
		if (res.done || !res.value || res.value[0] !== 0x05) throw new Error("پاسخ نامعتبر از سرور (پـروکـسـی SOCKS5 نیست یا خاموش است)");
		const method = res.value[1];
		if (method === 0x02) {
			const uEnc = new TextEncoder().encode(user);
			const pEnc = new TextEncoder().encode(pass);
			const authReq = new Uint8Array(1 + 1 + uEnc.length + 1 + pEnc.length);
			authReq[0] = 0x01;
			authReq[1] = uEnc.length;
			authReq.set(uEnc, 2);
			authReq[2 + uEnc.length] = pEnc.length;
			authReq.set(pEnc, 3 + uEnc.length);
			await writer.write(authReq);
			let authRes = await reader.read();
			if (authRes.done || !authRes.value || authRes.value[1] !== 0x00) throw new Error("نام کاربری یا رمز عبور پـروکـسـی اشتباه است");
		}
		let addrType = 0x03;
		let addrBytes;
		if (isIPv4(destAddr)) {
			addrType = 0x01;
			addrBytes = new Uint8Array(destAddr.split(".").map(Number));
		} else if (destAddr.includes(":")) {
			addrType = 0x04;
			addrBytes = new Uint8Array(16);
			const blocks = destAddr.split(":");
			for (let i = 0; i < 8; i++) {
				const val = parseInt(blocks[i] || "0", 16);
				addrBytes[i * 2] = (val >> 8) & 0xff;
				addrBytes[i * 2 + 1] = val & 0xff;
			}
		} else {
			const enc = new TextEncoder().encode(destAddr);
			addrBytes = new Uint8Array(1 + enc.length);
			addrBytes[0] = enc.length;
			addrBytes.set(enc, 1);
		}
		const req = new Uint8Array(4 + addrBytes.length + 2);
		req[0] = 0x05;
		req[1] = 0x01;
		req[2] = 0x00;
		req[3] = addrType;
		req.set(addrBytes, 4);
		const portOffset = 4 + addrBytes.length;
		req[portOffset] = (destPort >> 8) & 0xff;
		req[portOffset + 1] = destPort & 0xff;
		await writer.write(req);
		let connRes = await reader.read();
		if (connRes.done || !connRes.value || connRes.value[1] !== 0x00) throw new Error("پـروکـسـی وصل شد اما دسترسی به اینترنت آزاد ندارد");
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}
async function connectHttp(proxyStr, destAddr, destPort, initialData) {
	const { user, pass, host, port, auth } = parseProxyConfig(proxyStr, 80);
	const socket = connect({ hostname: host, port: port });
	const reader = socket.readable.getReader();
	const writer = socket.writable.getWriter();
	try {
		const safeDest = destAddr.includes(":") ? `[${destAddr}]` : destAddr;
		let req = `CONNECT ${safeDest}:${destPort} HTTP/1.1\r\nHost: ${safeDest}:${destPort}\r\n`;
		if (auth) {
			const authBase64 = btoa(`${user}:${pass}`);
			req += `Proxy-Authorization: Basic ${authBase64}\r\n`;
		}
		req += "\r\n";
		await writer.write(new TextEncoder().encode(req));
		let resStr = "";
		while (true) {
			const res = await reader.read();
			if (res.done || !res.value) throw new Error("proxy_closed");
			resStr += new TextDecoder().decode(res.value, { stream: true });
			if (resStr.includes("\r\n\r\n")) {
				const match = resStr.match(/^HTTP\/\d\.\d\s+(\d+)/);
				if (match && match[1] === "200") {
					break;
				} else {
					throw new Error("proxy_error_" + (match ? match[1] : "unknown"));
				}
			}
		}
		if (initialData && initialData.byteLength > 0) {
			await writer.write(convertToUint8Array(initialData));
		}
		writer.releaseLock();
		reader.releaseLock();
		return socket;
	} catch (e) {
		try {
			writer.releaseLock();
		} catch (err) {}
		try {
			reader.releaseLock();
		} catch (err) {}
		try {
			socket.close();
		} catch (err) {}
		throw e;
	}
}

return __WORKER_EXPORT__;

})(connect);
export default __CYRUS_WORKER__;
