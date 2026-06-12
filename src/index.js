/**
 * FlareDrive-R2 Worker 入口
 * 整合所有API路由和静态文件服务
 */

// ============================================================
// S3 客户端工具 (从 utils/s3.ts 转换)
// ============================================================

function arrayBufferToHex(arrayBuffer) {
  return [...new Uint8Array(arrayBuffer)]
    .map((x) => x.toString(16).padStart(2, "0"))
    .join("");
}

async function hmacSHA256(secret, message) {
  if (typeof message === "string") message = new TextEncoder().encode(message);
  const key = await crypto.subtle.importKey(
    "raw",
    secret,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const signature = await crypto.subtle.sign("HMAC", key, message);
  return signature;
}

class S3Client {
  constructor(accessKeyId, secretAccessKey, region) {
    this.accessKeyId = accessKeyId;
    this.secretAccessKey = secretAccessKey;
    this.region = region || "auto";
  }

  async s3_fetch(input, init) {
    init = init || {};
    const url = new URL(input);
    const objectKey = decodeURI(url.pathname);
    const method = init.method || "GET";
    const canonicalQueryString = [...url.searchParams]
      .map(
        ([key, value]) =>
          encodeURIComponent(key) + "=" + encodeURIComponent(value)
      )
      .join("&");
    const hashedPayload = "UNSIGNED-PAYLOAD";
    const headers = new Headers(init.headers);
    const datetime = new Date().toISOString().replace(/-|:|\.\d+/g, "");
    headers.set("x-amz-date", datetime);
    headers.set("x-amz-content-sha256", hashedPayload);
    headers.set("host", url.host);
    const signedHeaderKeys = [...headers.keys()].filter(
      (header) =>
        header === "host" ||
        header === "content-type" ||
        header.startsWith("x-amz-")
    );
    const canonicalHeaders = signedHeaderKeys
      .map((key) => `${key}:${headers.get(key)}\n`)
      .join("");
    const signedHeaders = signedHeaderKeys.join(";");
    const canonicalUri = encodeURIComponent(objectKey)
      .replaceAll("%2F", "/")
      .replace(/[!*'()]/g, function (c) {
        return "%" + c.charCodeAt(0).toString(16).toUpperCase();
      });
    const canonicalRequest = [
      method,
      canonicalUri,
      canonicalQueryString,
      canonicalHeaders,
      signedHeaders,
      hashedPayload,
    ].join("\n");

    const hashedRequest = arrayBufferToHex(
      await crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(canonicalRequest)
      )
    );
    const scope = `${datetime.slice(0, 8)}/${this.region}/s3/aws4_request`;
    const stringToSign = [
      "AWS4-HMAC-SHA256",
      datetime,
      scope,
      hashedRequest,
    ].join("\n");

    const dateKey = await hmacSHA256(
      new TextEncoder().encode("AWS4" + this.secretAccessKey),
      datetime.slice(0, 8)
    );
    const dateRegionKey = await hmacSHA256(dateKey, this.region);
    const dateRegionServiceKey = await hmacSHA256(dateRegionKey, "s3");
    const signingKey = await hmacSHA256(dateRegionServiceKey, "aws4_request");
    const signature = arrayBufferToHex(await hmacSHA256(signingKey, stringToSign));

    const credential = `${this.accessKeyId}/${scope}`;
    const authorizationString = `AWS4-HMAC-SHA256 Credential=${credential},SignedHeaders=${signedHeaders},Signature=${signature}`;

    headers.set("Authorization", authorizationString);
    init.headers = headers;
    return fetch(input, init);
  }
}

// ============================================================
// 认证/授权工具 (从 utils/auth.ts 转换)
// ============================================================

const THUMBNAIL_PREFIX = "_$flaredrive$/thumbnails/";

function parseAllowList(value) {
  if (!value) return [];
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0);
}

function matchesAllowList(targetPath, allowList) {
  if (allowList.includes("*")) return true;
  return allowList.some((allow) => targetPath.startsWith(allow));
}

function getAllowListForRequest(context) {
  const headers = new Headers(context.request.headers);
  const authorization = headers.get("Authorization");
  if (authorization && authorization.startsWith("Basic ")) {
    const account = atob(authorization.split("Basic ")[1]);
    if (account && context.env[account]) {
      return parseAllowList(context.env[account]);
    }
  }
  if (context.env["GUEST"]) {
    return parseAllowList(context.env["GUEST"]);
  }
  return null;
}

function can_access_path(context, targetPath) {
  if (targetPath.startsWith(THUMBNAIL_PREFIX)) return true;
  const allowList = getAllowListForRequest(context);
  if (!allowList) return false;
  return matchesAllowList(targetPath, allowList);
}

function get_allow_list(context) {
  return getAllowListForRequest(context);
}

function get_auth_status(context) {
  const dopath = context.request.url.split("/api/write/items/")[1];
  if (!dopath) return false;
  return can_access_path(context, dopath);
}

// ============================================================
// 存储桶工具 (从 utils/bucket.ts 转换)
// ============================================================

function notFound() {
  return new Response("Not found", { status: 404 });
}

function parseBucketPath(context) {
  const { request, env, params } = context;
  const url = new URL(request.url);

  const pathSegments = params.path || [];
  const path = decodeURIComponent(pathSegments.join("/"));
  const driveid = url.hostname.replace(/\..*/, "");

  return [env[driveid] || env["BUCKET"], path];
}

// ============================================================
// CORS 响应头
// ============================================================

const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, POST, PUT, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
};

// ============================================================
// API 路由处理器
// ============================================================

// GET /api/buckets
async function handleBuckets(context) {
  try {
    const { request, env } = context;
    const url = new URL(request.url);

    if (url.searchParams.has("current")) {
      const driveid = url.hostname.replace(/\..*/, "");
      if (!(await env[driveid].head("_$flaredrive$/CNAME")))
        await env[driveid].put("_$flaredrive$/CNAME", url.hostname);

      const client = new S3Client(env.AWS_ACCESS_KEY_ID, env.AWS_SECRET_ACCESS_KEY);
      const bucketsResponse = await client.s3_fetch(
        `https://${env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com/`
      );
      const bucketsText = await bucketsResponse.text();
      const bucketNames = [
        ...bucketsText.matchAll(/<Name>([0-9a-z-]*)<\/Name>/g),
      ].map((match) => match[1]);
      const currentBucket = await Promise.any(
        bucketNames.map(
          (name) =>
            new Promise((resolve, reject) => {
              client
                .s3_fetch(
                  `https://${env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com/${name}/_$flaredrive$/CNAME`
                )
                .then((response) => response.text())
                .then((text) => {
                  if (text === url.hostname) resolve(name);
                  else reject();
                })
                .catch(() => reject());
            })
        )
      );

      return new Response(currentBucket, {
        headers: { "cache-control": "max-age=604800" },
      });
    }

    const client = new S3Client(
      env.AWS_ACCESS_KEY_ID,
      env.AWS_SECRET_ACCESS_KEY
    );
    return client.s3_fetch(
      `https://${env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com/`
    );
  } catch (e) {
    return new Response(e.toString(), { status: 500 });
  }
}

// GET /api/children/*
async function handleChildren(context) {
  try {
    const [bucket, path] = parseBucketPath(context);
    const prefix = path && `${path}/`;
    if (!bucket || prefix.startsWith("_$flaredrive$/")) return notFound();
    const allowList = get_allow_list(context);
    if (!allowList) {
      const headers = new Headers();
      headers.set("WWW-Authenticate", 'Basic realm="需要登录"');
      return new Response("没有读取权限", { status: 401, headers });
    }
    if (prefix && !can_access_path(context, prefix)) {
      const headers = new Headers();
      headers.set("WWW-Authenticate", 'Basic realm="需要登录"');
      return new Response("没有读取权限", { status: 401, headers });
    }

    const objList = await bucket.list({
      prefix,
      delimiter: "/",
      include: ["httpMetadata", "customMetadata"],
    });
    let objKeys = objList.objects
      .filter((obj) => !obj.key.endsWith("/_$folder$"))
      .map((obj) => {
        const { key, size, uploaded, httpMetadata, customMetadata } = obj;
        return { key, size, uploaded, httpMetadata, customMetadata };
      });

    let folders = objList.delimitedPrefixes;
    if (!path)
      folders = folders.filter((folder) => folder !== "_$flaredrive$/");
    if (!allowList.includes("*") && !path) {
      objKeys = objKeys.filter((obj) =>
        allowList.some((allow) => obj.key.startsWith(allow))
      );
      folders = folders.filter((folder) =>
        allowList.some((allow) => folder.startsWith(allow))
      );
      for (const allow of allowList) {
        if (!folders.includes(allow)) folders.push(allow);
      }
    }

    return new Response(JSON.stringify({ value: objKeys, folders }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (e) {
    return new Response(e.toString(), { status: 500 });
  }
}

// POST /api/write/items/* (创建分片上传 / 完成分片上传)
async function handleWriteItemsPost(context) {
  const url = new URL(context.request.url);
  const searchParams = new URLSearchParams(url.search);

  if (searchParams.has("uploads")) {
    // 创建分片上传
    const [bucket, path] = parseBucketPath(context);
    if (!bucket) return notFound();

    const request = context.request;
    const customMetadata = {};
    if (request.headers.has("fd-thumbnail"))
      customMetadata.thumbnail = request.headers.get("fd-thumbnail");

    const multipartUpload = await bucket.createMultipartUpload(path, {
      httpMetadata: {
        contentType: request.headers.get("content-type"),
      },
      customMetadata,
    });

    return new Response(
      JSON.stringify({
        key: multipartUpload.key,
        uploadId: multipartUpload.uploadId,
      })
    );
  }

  if (searchParams.has("uploadId")) {
    // 完成分片上传
    const [bucket, path] = parseBucketPath(context);
    if (!bucket) return notFound();

    const request = context.request;
    const uploadId = new URLSearchParams(new URL(request.url).search).get("uploadId");
    const multipartUpload = await bucket.resumeMultipartUpload(path, uploadId);

    const completeBody = await request.json();

    try {
      const object = await multipartUpload.complete(completeBody.parts);
      return new Response(null, {
        headers: { etag: object.httpEtag },
      });
    } catch (error) {
      return new Response(error.message, { status: 400 });
    }
  }

  return new Response("Method not allowed", { status: 405 });
}

// PUT /api/write/items/* (上传文件 / 上传分片)
async function handleWriteItemsPut(context) {
  if (!get_auth_status(context)) {
    const header = new Headers();
    header.set("WWW-Authenticate", 'Basic realm="需要登录"');
    return new Response("没有操作权限", {
      status: 401,
      headers: header,
    });
  }

  const url = new URL(context.request.url);

  if (new URLSearchParams(url.search).has("uploadId")) {
    // 上传分片
    const [bucket, path] = parseBucketPath(context);
    if (!bucket) return notFound();

    const request = context.request;
    const uploadId = new URLSearchParams(new URL(request.url).search).get("uploadId");
    const multipartUpload = await bucket.resumeMultipartUpload(path, uploadId);

    const partNumber = parseInt(
      new URLSearchParams(new URL(request.url).search).get("partNumber")
    );
    const uploadedPart = await multipartUpload.uploadPart(
      partNumber,
      request.body
    );

    return new Response(null, {
      headers: {
        "Content-Type": "application/json",
        etag: uploadedPart.etag,
      },
    });
  }

  // 普通上传
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const request = context.request;

  let content = request.body;
  const customMetadata = {};

  if (request.headers.has("x-amz-copy-source")) {
    const sourceName = decodeURIComponent(
      request.headers.get("x-amz-copy-source")
    );
    const source = await bucket.get(sourceName);
    content = source.body;
    if (source.customMetadata.thumbnail)
      customMetadata.thumbnail = source.customMetadata.thumbnail;
  }

  if (request.headers.has("fd-thumbnail"))
    customMetadata.thumbnail = request.headers.get("fd-thumbnail");

  const obj = await bucket.put(path, content, { customMetadata });
  const { key, size, uploaded } = obj;
  return new Response(JSON.stringify({ key, size, uploaded }), {
    headers: { "Content-Type": "application/json" },
  });
}

// DELETE /api/write/items/*
async function handleWriteItemsDelete(context) {
  if (!get_auth_status(context)) {
    const header = new Headers();
    header.set("WWW-Authenticate", 'Basic realm="需要登录"');
    return new Response("没有操作权限", {
      status: 401,
      headers: header,
    });
  }
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  await bucket.delete(path);
  return new Response(null, { status: 204 });
}

// ALL /api/write/s3/*
async function handleWriteS3(context) {
  const { request, env } = context;

  const client = new S3Client(env.AWS_ACCESS_KEY_ID, env.AWS_SECRET_ACCESS_KEY);
  const forwardUrl = request.url.replace(
    /.*\/api\/write\/s3\//,
    `https://${env.CF_ACCOUNT_ID}.r2.cloudflarestorage.com/`
  );

  return client.s3_fetch(forwardUrl, {
    method: request.method,
    body: request.body,
    headers: request.headers,
  });
}

// ALL /api/write/test/*
async function handleWriteTest(context) {
  if (!get_auth_status(context)) {
    const header = new Headers();
    header.set("WWW-Authenticate", 'Basic realm="需要登录"');
    return new Response("没有操作权限", {
      status: 401,
      headers: header,
    });
  }

  return new Response("access", {
    status: 200,
  });
}

// GET /raw/*
async function handleRaw(context) {
  const [bucket, path] = parseBucketPath(context);
  if (!bucket) return notFound();

  const url = context.env["PUBURL"] + "/" + context.request.url.split("/raw/")[1];

  const response = await fetch(new Request(url, {
    body: context.request.body,
    headers: context.request.headers,
    method: context.request.method,
    redirect: "follow",
  }));


  const headers = new Headers(response.headers);
  if (path.startsWith("_$flaredrive$/thumbnails/")) {
    headers.set("Cache-Control", "max-age=31536000");
  }

  return new Response(response.body, {
    headers: headers,
    status: response.status,
    statusText: response.statusText
  });
}

// ============================================================
// 主 Worker 入口
// ============================================================

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    // 处理 CORS 预检请求
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }

    try {
      // 构建上下文（兼容 Pages Functions 格式）
      const context = {
        request,
        env,
        ctx,
        params: {},
      };

      // API 路由匹配
      
      // /api/buckets
      if (url.pathname === "/api/buckets") {
        if (request.method === "GET") {
          return await handleBuckets(context);
        }
        return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
      }

      // /api/children/*
      const childrenMatch = url.pathname.match(/^\/api\/children\/(.*)$/);
      if (childrenMatch) {
        context.params.path = childrenMatch[1] ? childrenMatch[1].split("/") : [];
        if (request.method === "GET") {
          return await handleChildren(context);
        }
        return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
      }

      // /api/write/items/*
      const writeItemsMatch = url.pathname.match(/^\/api\/write\/items\/(.*)$/);
      if (writeItemsMatch) {
        context.params.path = writeItemsMatch[1] ? writeItemsMatch[1].split("/") : [];
        if (request.method === "POST") {
          return await handleWriteItemsPost(context);
        }
        if (request.method === "PUT") {
          return await handleWriteItemsPut(context);
        }
        if (request.method === "DELETE") {
          return await handleWriteItemsDelete(context);
        }
        return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
      }

      // /api/write/s3/*
      const writeS3Match = url.pathname.match(/^\/api\/write\/s3\/(.*)$/);
      if (writeS3Match) {
        context.params.path = writeS3Match[1] ? writeS3Match[1].split("/") : [];
        return await handleWriteS3(context);
      }

      // /api/write/test/*
      const writeTestMatch = url.pathname.match(/^\/api\/write\/test\/(.*)$/);
      if (writeTestMatch) {
        context.params.path = writeTestMatch[1] ? writeTestMatch[1].split("/") : [];
        return await handleWriteTest(context);
      }

      // /raw/*
      const rawMatch = url.pathname.match(/^\/raw\/(.*)$/);
      if (rawMatch) {
        context.params.path = rawMatch[1] ? rawMatch[1].split("/") : [];
        if (request.method === "GET") {
          return await handleRaw(context);
        }
        return new Response("Method Not Allowed", { status: 405, headers: corsHeaders });
      }

      // 非 API 请求 -> 交给静态资源 (ASSETS 绑定)
      // 这会返回 public 目录下的 index.html, assets/ 等文件
      return env.ASSETS.fetch(request);

    } catch (e) {
      return new Response(e.toString(), { status: 500, headers: corsHeaders });
    }
  },
};
