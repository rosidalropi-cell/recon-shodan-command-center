export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, OPTIONS",
      "Access-Control-Allow-Headers": "Content-Type",
      "Cache-Control": "no-store"
    };
    const json = (data, status = 200) => new Response(JSON.stringify(data), {
      status, headers: { ...cors, "Content-Type": "application/json; charset=utf-8" }
    });
    if (request.method === "OPTIONS") return new Response(null, { headers: cors });
    if (url.pathname === "/api/health") {
      return json({ ok: true, service: "recon-shodan-osint", time: new Date().toISOString(), shodanConfigured: Boolean(env.SHODAN_API_KEY) });
    }
    if (url.pathname === "/api/recon") {
      const target = (url.searchParams.get("target") || "").trim();
      if (!validTarget(target)) return json({ error: "Target tidak valid. Masukkan domain atau IP tanpa URL/path." }, 400);
      const domain = target.replace(/^\[|\]$/g, "");
      const types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME"];
      const records = [];
      for (const type of types) {
        try {
          const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${type}`, {
            headers: { "accept": "application/dns-json" },
            cf: { cacheTtl: 60, cacheEverything: true }
          });
          if (r.ok) {
            const d = await r.json();
            records.push({ type, Status: d.Status, Answer: d.Answer || [] });
          }
        } catch (_) { /* one record type failing should not hide other DNS results */ }
      }
      return json({ target, queriedAt: new Date().toISOString(), source: "Cloudflare public DNS-over-HTTPS", records });
    }
    if (url.pathname === "/api/shodan/host") {
      const target = (url.searchParams.get("target") || "").trim();
      if (!validTarget(target)) return json({ error: "Target tidak valid." }, 400);
      if (!env.SHODAN_API_KEY) return json({ error: "SHODAN_API_KEY belum disetel sebagai Worker secret. Jangan taruh API key di index.html atau GitHub." }, 503);
      const ip = await resolveToIp(target);
      if (!ip) return json({ error: "Target tidak berhasil di-resolve ke IPv4. Coba alamat IP langsung." }, 400);
      const shodanUrl = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${encodeURIComponent(env.SHODAN_API_KEY)}`;
      const r = await fetch(shodanUrl, { headers: { "Accept": "application/json" } });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) {
        const msg = r.status === 401 || r.status === 403 ? "Shodan menolak API key atau akses endpoint." :
                    r.status === 404 ? "Shodan tidak memiliki data host untuk IP ini." :
                    r.status === 429 ? "Kuota atau rate limit Shodan tercapai." : `Shodan API HTTP ${r.status}`;
        return json({ error: msg, status: r.status, detail: data.error || null }, r.status === 404 ? 404 : r.status === 429 ? 429 : r.status === 401 || r.status === 403 ? 403 : 502);
      }
      return json(data);
    }
    // Serve static website files from the configured public directory.
    return env.ASSETS.fetch(request);
  }
};
function validTarget(s) {
  return Boolean(s) && s.length <= 253 && /^[a-zA-Z0-9.:[\]-]+$/.test(s) &&
    !s.includes("..") && !s.startsWith(".") && !s.endsWith(".");
}
async function resolveToIp(target) {
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(target)) return target;
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(target)}&type=A`, {
    headers: { "accept": "application/dns-json" }
  });
  if (!r.ok) return null;
  const d = await r.json();
  return (d.Answer || []).find(a => a.type === 1 && /^\d{1,3}(?:\.\d{1,3}){3}$/.test(a.data))?.data || null;
}
