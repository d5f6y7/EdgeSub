import { fetchCached } from "../internal/utils/fetchCached.js";

const ALLOWED_TARGET_HOSTS = new Set([
    "raw.githubusercontent.com",
    "github.com"
]);

export async function onRequest (context) {
    const { request } = context;
    const URLObject = new URL(request.url);

    const targetURL = URLObject.searchParams.get("target") as unknown as URL;

    if (!targetURL) {
        return new Response("400 Bad Request. 'targetURL' required.", {
            status: 200,
            headers: {
                "Content-Type": "text/plain; charset=utf-8"
            }
        })
    }

    let ParsedTarget: URL;
    try {
        ParsedTarget = new URL(targetURL as unknown as string);
    } catch {
        return new Response("400 Bad Request. 'target' is not a valid URL.", {
            status: 400,
            headers: {
                "Content-Type": "text/plain; charset=utf-8"
            }
        })
    }
    if (ParsedTarget.protocol !== "https:" || !ALLOWED_TARGET_HOSTS.has(ParsedTarget.hostname)) {
        return new Response("403 Forbidden. target host is not allowed.", {
            status: 403,
            headers: {
                "Content-Type": "text/plain; charset=utf-8"
            }
        })
    }

    let RawData = await fetch(ParsedTarget);
    return new Response(RawData.body, {
        status: 200,
        headers: RawData.headers
    })
}
