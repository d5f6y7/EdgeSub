export class ShareLinkParser {
    constructor () {}

    __validate (URI) {
        if (!(URI.split(":")[0] in this)) {
            console.warn(`[Parser: Share Link] [WARN] ${URI.__Type} is not supported to parse, ignoring...`)
            return false;
        }
        return true;
    }

    http (URI) {
        let URIObject = new URL (URI);
        return {
            __Type: "http",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Auth: {
                username: URIObject.username,
                password: URIObject.password
            }
        }
    }
    socks5 (URI) {
        let URIObject = new URL (URI);
        return {
            __Type: "socks5",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Auth: {
                username: URIObject.username,
                password: URIObject.password
            }
        }
    }
    
    hysteria (HYURL) {
        const URIObject = new URL (HYURL);

        const HY = {
            __Type: "hysteria",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Query: __searchParamsMapper(URIObject.searchParams)
        }
        return HY;
    }
    hysteria2 (HY2URL) {
        const URIObject = new URL (HY2URL);

        const HY2 = {
            __Type: "hysteria2",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Auth: decodeURIComponent(URIObject.password || URIObject.username),
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Query: __searchParamsMapper(URIObject.searchParams)
        }
        return HY2;
    }
    hy2 = this.hysteria2;

    anytls (ATURL) {
        const URIObject = new URL (ATURL);

        return {
            __Type: "anytls",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Auth: decodeURIComponent(URIObject.password || URIObject.username),
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Query: __searchParamsMapper(URIObject.searchParams)
        }
    }

    tuic (TUICURI) {
        let URIObject = new URL(TUICURI);

        const TUIC = {
            __Type: "tuic",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Auth: { uuid: URIObject.username, password: URIObject.password},
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Query: __searchParamsMapper(URIObject.searchParams)
        }
        return TUIC;
    }


    vless (URI) {
        let URIObject = new URL (URI);
        let VLESS = {
            __Type: "vless",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Auth: URIObject.username,
            Query: __searchParamsMapper(URIObject.searchParams)
        }
        return VLESS;
    }
    vmess (URI) {
        let URIObject = new URL(URI);
        let VMessRawData = atob(URIObject.host);
        try {
            let VMessRawObject = JSON.parse(VMessRawData);

            let Remark;
            try {
                Remark = decodeURIComponent(escape(VMessRawObject.ps))
            } catch (e) {
                Remark = VMessRawObject.ps
            }
            let VMess =  {
                __Type: "vmess",
                __Remark: Remark || `${VMessRawObject.add}:${VMessRawObject.port}`,
                Hostname: VMessRawObject.add,
                Port: parseInt(VMessRawObject.port),
                Auth: VMessRawObject.id,
            }
            delete VMessRawObject.ps
            delete VMessRawObject.add
            delete VMessRawObject.port
            delete VMessRawObject.id

            // am i doing right...
            delete VMessRawObject.v // assume its version 2

            // delete all the empty fields
            for (let i in VMessRawObject) {
                if (
                    VMessRawObject[i] === "" || 
                    VMessRawObject[i] === null || 
                    VMessRawObject[i] === undefined
                ) {
                    delete VMessRawObject[i]
                }
            }

            VMessRawObject.aid = parseInt(VMessRawObject.aid)

            VMess.Query = VMessRawObject;

            return VMess;
        } catch (err) {
            let StandardURIObj = new URL(`vmess://${VMessRawData}${URIObject.pathname}${URIObject.search}`)
            let VMess =  {
                //__Type: "vmess",
                __Type: "vmess__shadowsocks_type",
                __Remark: StandardURIObj.searchParams.get("remarks") || StandardURIObj.host,
                Hostname: StandardURIObj.hostname,
                Port: parseInt(StandardURIObj.port),
                Auth: StandardURIObj.password,
                Query: __searchParamsMapper(URIObject.searchParams)
            }
            delete VMess.Query.remarks
            if (VMess.Query.obfs === "websocket") { VMess.Query.obfs = "ws" }
            return VMess
        }
    }

    ss (URI) {
        let StandardURI = (URI => {
            let URIObject = new URL(URI);
            try {
                // base64-encoded cipher:uuid@host:port
                return `ss://${encodeURIComponent(atob(decodeURIComponent(URIObject.host))).replace(/\%3A/gi,":").replace(/\%40/gi,"@")}${URIObject.search}${URIObject.hash}`;
            } catch (e) {}
            try {
                // base64-encoded cipher:uuid
                return `ss://${encodeURIComponent(atob(decodeURIComponent(URIObject.username))).replace(/\%3A/i,":")}@${URIObject.host}${URIObject.search}${URIObject.hash}`;
            } catch (e) {}
            // plain
            return URI;
        })(URI)
        
        let URIObject = new URL(StandardURI);
        

        return {
            __Type: "ss",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Auth: { cipher: decodeURIComponent(URIObject.username), password: decodeURIComponent(URIObject.password) },
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port)
        }

    }

    trojan (URI) {
        let URIObject = new URL(URI);

        const TROJAN = {
            __Type: "trojan",
            __Remark: decodeURIComponent(URIObject.hash.replace(/^#/, "")) || URIObject.host,
            Auth: URIObject.username,
            Hostname: URIObject.hostname,
            Port: parseInt(URIObject.port),
            Query: __searchParamsMapper(URIObject.searchParams)
        }
        return TROJAN;
    }

    ssr (SSRURI) {
        // ssr://base64url(host:port:protocol:method:obfs:base64url(password)/?remarks=..&protoparam=..&obfsparam=..&group=..)
        let Raw = SSRURI.replace(/^ssr:\/\//i, "");

        // params after "/?" carry base64url values, still encoded at this stage
        let EncodedParams = "";
        let SeparatorIndex = Raw.indexOf("/?");
        if (SeparatorIndex !== -1) {
            EncodedParams = Raw.slice(SeparatorIndex + 2);
            Raw = Raw.slice(0, SeparatorIndex);
        }

        let Main = __b64UrlDecode(Raw);

        // some clients put everything (incl. "/?params") inside the base64
        let DecodedParams = "";
        SeparatorIndex = Main.indexOf("/?");
        if (SeparatorIndex !== -1) {
            DecodedParams = Main.slice(SeparatorIndex + 2);
            Main = Main.slice(0, SeparatorIndex);
        }

        const Params = {};
        for (const Encoded of [DecodedParams, EncodedParams]) {
            if (!Encoded) { continue; }
            for (const [key, value] of new URLSearchParams(Encoded)) {
                Params[key] = value;
            }
        }

        // host may contain ":" (ipv6); the last 5 segments are port/protocol/method/obfs/password
        const Segments = Main.split(":");
        const PasswordB64 = Segments.pop();
        const Obfs = Segments.pop();
        const Method = Segments.pop();
        const Protocol = Segments.pop();
        const Port = Segments.pop();
        const Host = Segments.join(":");

        return {
            __Type: "ssr",
            __Remark: Params.remarks ? __b64UrlDecode(Params.remarks) : Host,
            Hostname: Host,
            Port: parseInt(Port),
            Auth: { cipher: Method, password: __b64UrlDecode(PasswordB64 || "") },
            Query: {
                protocol: Protocol,
                obfs: Obfs,
                "protocol-param": Params.protoparam ? __b64UrlDecode(Params.protoparam) : undefined,
                "obfs-param": Params.obfsparam ? __b64UrlDecode(Params.obfsparam) : undefined,
                group: Params.group ? __b64UrlDecode(Params.group) : undefined,
            }
        }
    }
}

function __searchParamsMapper (searchParams) {
    let Query = {}
    for (const [key, value] of searchParams) {
        Query[key] = value
    }
    return Query;
}

function __b64UrlDecode (str) {
    const Normalized = String(str).replace(/-/g, "+").replace(/_/g, "/");
    const Padded = Normalized + "=".repeat((4 - (Normalized.length % 4)) % 4);
    const Binary = atob(Padded);
    return new TextDecoder("utf-8").decode(Uint8Array.from(Binary, (c) => c.charCodeAt(0)));
}