import os from 'node:os'
import { exec } from 'node:child_process'
import path from 'node:path'
import { mkdir, rm } from 'node:fs/promises'
import http from 'node:http'
import { Buffer } from 'node:buffer'
import crypto from 'node:crypto'
import { fetchSecretsAws } from '@harboor/core'
import { customAlphabet } from 'nanoid'

(async function initServer() {
    const HOME_PATH = os.homedir()
    const DEPLOYMENTS_PATH = path.resolve(HOME_PATH, 'deployments')
    await mkdir(DEPLOYMENTS_PATH, { recursive: true })

    const secrets =
        process.env.NODE_ENV === "development"
            ? process.env
            : await fetchSecretsAws({
                aws: {
                    secretName: process.env.AWS_SECRET_NAME,
                    credentials: {
                        region: process.env.AWS_REGION,
                        accessKey: process.env.AWS_ACCESS_KEY,
                        accessKeySecret: process.env.AWS_ACCESS_KEY_SECRET,
                    },
                },
            });
    const env = createEnvironment(secrets);
    const apps = [
        { name: 'harboorio/auth-backend', aws: { secretName: 'prod/harboor/auth' }, gitBranch: 'main', gitCheckout: ['compose.yaml'] }
    ]
    const server = http.createServer({
        keepAliveTimeout: 30000,
        requestTimeout: 60000,
    })

    server.on('request', async function onRequest(req, res) {
        console.log(req.method + ' ' + req.url)

        res
            .setHeader("Referrer-Policy", "strict-origin-when-cross-origin")
            .setHeader("Strict-Transport-Security", "max-age=31536000")
            .setHeader("Vary", "Origin,Accept-Language");

        if (req.method !== 'POST' && req.url !== '/on/release') {
            res.statusCode = 400
            return res.end('Invalid request.')
        }

        const signature = req.headers['x-hub-signature-256']
        if (!signature) {
            res.statusCode = 400
            return res.end('Missing signature.')
        }

        const bodyBuffer = await readBody(req)
        const bodyString = bodyBuffer.data.toString()

        if (!verifySignature(bodyString, signature)) {
            res.statusCode = 400
            return res.end('Invalid signature.')
        }

        let body;
        try {
            body = JSON.parse(bodyString)
        } catch (e) {
            res.statusCode = 400
            return res.end('Invalid body.')
        }

        const isVerifiedAppRelease = body?.action === 'published' && body?.release && apps.some((app) => app.name === body.repository.full_name)

        if (!isVerifiedAppRelease) {
            res.statusCode = 200
            return res.end(`Couldn't find the verified application.`)
        }

        console.log('Deploying ' + body.repository.full_name + ':' + body.release.tag_name)
        const app = apps.find((app) => app.name === body.repository.full_name)
        await deploy(app, body, function onDone(error, statusCode, msg) {
            if (error) {
                console.error(error)
            }
            res.statusCode = statusCode
            return res.end(msg)
        })
    })

    server.on("dropRequest", onDropRequest);
    server.on("clientError", onClientError);

    server.listen(env.get('SERVER_PORT') ?? 3000, "0.0.0.0", () => {
        console.info("Server is online.");
    });

    async function deploy(app, event, onDone) {
        const tag = event.release.tag_name.replace(/[^0-9.]*/g, '')
        const nameUrlSafe = app.name
            .replace(/[^a-z0-9A-Z-_]/g, '-')
            .replace(/(^[-]+)|([-]+$)/g, '')
        const pathName = ['prod', nameUrlSafe, event.release.tag_name, generateDeploymentSuffix()].join('-')
        const DEPLOYMENT_PATH = path.resolve(DEPLOYMENTS_PATH, pathName)
        await mkdir(DEPLOYMENT_PATH, { recursive: true })

        const commands = [
            'git clone --filter=blob:none --no-checkout ' + event.repository.clone_url + ' .',
            'git sparse-checkout init --cone',
            'git sparse-checkout set ' + app.gitCheckout.join(' '),
            'git checkout ' + app.gitBranch
        ]
        exec(commands.join(' && '), { cwd: DEPLOYMENT_PATH }, async (error, stdout, stderr) => {
            if (error) {
                return onDone(error, 400, 'Failed to checkout to the repository.')
            }

            console.log(stderr)
            console.log(stdout)

            const secretsFilePath = path.resolve(DEPLOYMENT_PATH, '.env')
            await fetchSecretsAws({
                dest: secretsFilePath,
                aws: {
                    secretName: app.aws.secretName,
                    credentials: {
                        region: process.env.AWS_REGION,
                        accessKey: process.env.AWS_ACCESS_KEY,
                        accessKeySecret: process.env.AWS_ACCESS_KEY_SECRET,
                    },
                },
            })

            const commands2 = ['APP_IMAGE_VERSION=' + tag + ' docker compose --profile production up -d']
            exec(commands2.join(' && '), { cwd: DEPLOYMENT_PATH }, async (error2, stdout2, stderr2) => {
                await rm(secretsFilePath)

                if (error2) {
                    return onDone(error2, 400, 'Failed to start compose services.')
                }

                console.log(stderr2)
                console.log(stdout2)

                return onDone(null, 200, 'Success.')
            })
        })

        function generateDeploymentSuffix() {
            return customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 6)()
        }
    }

    function verifySignature(body, signature) {
        const hmac = crypto.createHmac('sha256', env.get('GITHUB_WEBHOOK_SECRET_TOKEN'))
        const calculatedSignature = 'sha256=' + hmac.update(body).digest('hex')
        return crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(calculatedSignature))
    }

    function createEnvironment(obj) {
        const env = new Map()
        Object.keys(obj).map((k) => env.set(k, obj[k]));
        return env;
    }

    async function readBody(req) {
        const HTTP_REQUEST_MAX_BODY_SIZE = 1000000

        return new Promise((resolve, reject) => {
            let cleaned = false;
            let received = 0;
            let chunks = [];

            req.on("error", onError);
            req.on("aborted", onAborted);
            req.on("data", onData);
            req.on("end", onEnd);
            req.on("close", onClose);

            function close(result) {
                resolve({
                    data: result instanceof Error ? null : result,
                    size: received,
                    err: result instanceof Error ? result : null,
                });
                return cleanup();
            }

            function cleanup() {
                if (cleaned) return;

                cleaned = true;
                received = 0;
                chunks = [];

                req.removeListener("error", onError);
                req.removeListener("aborted", onAborted);
                req.removeListener("data", onData);
                req.removeListener("end", onEnd);
                req.removeListener("close", onClose);
            }

            function onClose() {
                cleanup();
            }

            function onEnd() {
                return close(Buffer.concat(chunks));
            }

            function onData(chunk) {
                received += chunk.length;

                if (received > HTTP_REQUEST_MAX_BODY_SIZE) {
                    console.error("Max request body size exceeded.");
                    return close(new Error("request_body_size"));
                }

                chunks.push(chunk);
            }

            function onError(err) {
                const _err = new Error("request_stream_read", { cause: err });
                console.warn(_err, "Failed to read the request stream.");
                return close(_err);
            }

            function onAborted() {
                return close(new Error("request_aborted"));
            }
        });
    }

    function onDropRequest() {
        console.error("Dropped a request. Check server.maxRequestsPerSocket.");
    }

    function onClientError(err, socket) {
        if (err.code === "ECONNRESET" || !socket.writable) {
            return;
        }

        socket.end("HTTP/1.1 400 Bad Request\r\n\r\n");
    }
})();
