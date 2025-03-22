import os from 'node:os'
import { exec } from 'node:child_process'
import path from 'node:path'
import { mkdir, rm } from 'node:fs/promises'
import http from 'node:http'
import { Buffer } from 'node:buffer'
import crypto from 'node:crypto'
import { fetchSecretsAws } from '@harboor/core'
import { customAlphabet } from 'nanoid'
import { debounce } from 'underscore'

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
    const env = createEnvironment(secrets)

    console.log('Environment is ready.')

    const apps = [
        {
            name: 'harboorio/auth-backend',
            aws: {
                secretName: 'prod/harboor/auth'
            },
            git: {
                defaultBranch: 'main',
                partialClones: ['compose.yaml']
            }
        }
    ]

    let deployments = []
    const checkForDeploymentsDebounced = debounce(checkForDeployments, 3000)
    const deploymentsQueue = []

    setInterval(async () => {
        if (deploymentsQueue.length === 0) return

        const deployment = deploymentsQueue.shift()
        const _name = deployment.releaseEvent.repository.full_name + ':' + deployment.releaseEvent.release.tag_name
        console.log('Picking up the oldest entry in deployments (' + _name + ')')
        const result = await deploy(deployment.app, deployment.releaseEvent, deployment.packageEvent)
        if (result === true) console.log('Deployed ' + _name + ' successfully')
        else console.log(result)
    }, 3000)

    console.log('Watching deployment entries.')

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
            res.statusCode = 404
            return res.end('Not found')
        }

        const eventName = req.headers['x-github-event']
        const signature = req.headers['x-hub-signature-256']
        if (!eventName || !signature) {
            res.statusCode = 404
            return res.end('Invalid request')
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
            return res.end('Invalid request.')
        }

        // now we can tell github that we are "accepting" the request
        res.statusCode = 202
        res.end('Accepted')

        const app = findApp(body)

        if (!app) {
            return
        }

        const hookName = eventName + '_' + (body.action ?? '')

        switch (hookName) {
            case 'release_published':
                if (body?.release?.tag_name) {
                    deployments.push({ app, version: body.release.tag_name, releaseEvent: body, ready: false, queued: false })
                }
                break
            case 'package_published':
                if (body?.package?.package_type === 'CONTAINER' && body.package?.package_version?.container_metadata?.tag?.name) {
                    const packageTag = body.package.package_version.container_metadata.tag.name
                    const i = deployments.findIndex((d) => d.version.replace(/[^0-9.]*/g, '') === packageTag)
                    if (i > -1) {
                        deployments[i].packageEvent = body
                        deployments[i].ready = true
                    }
                }
                break
            default:
                return
        }

        checkForDeploymentsDebounced()
    })

    server.on("dropRequest", onDropRequest);
    server.on("clientError", onClientError);

    server.listen(env.get('SERVER_PORT') ?? 3000, "0.0.0.0", () => {
        console.info("Server (:" + (env.get('SERVER_PORT') ?? 3000) + ") is online.");
    });

    async function deploy(app, releaseEvent, packageEvent) {
        return new Promise(async (resolve, reject) => {
            // create deployment directory
            const tag = releaseEvent.release.tag_name.replace(/[^0-9.]*/g, '')
            const nameUrlSafe = app.name
                .replace(/[^a-z0-9A-Z-_]/g, '-')
                .replace(/(^[-]+)|([-]+$)/g, '')
            const pathName = ['prod', nameUrlSafe, releaseEvent.release.tag_name, generateDeploymentSuffix()].join('-')
            const DEPLOYMENT_PATH = path.resolve(DEPLOYMENTS_PATH, pathName)
            await mkdir(DEPLOYMENT_PATH, { recursive: true })

            // do partial clone for the deploy
            const commands = [
                'git clone --filter=blob:none --no-checkout ' + releaseEvent.repository.clone_url + ' .',
                'git sparse-checkout init --cone',
                'git sparse-checkout set ' + app.git.partialClones.join(' '),
                'git checkout ' + app.git.defaultBranch
            ]
            exec(commands.join(' && '), { cwd: DEPLOYMENT_PATH, timeout: 30000 }, async (error, stdout, stderr) => {
                if (error) {
                    return resolve(error)
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

                const commands2 = ['APP_IMAGE_VERSION=' + tag + ' docker compose --profile production up -d --quiet-pull -y']
                exec(commands2.join(' && '), { cwd: DEPLOYMENT_PATH, timeout: 30000 }, async (error2, stdout2, stderr2) => {
                    await rm(secretsFilePath)

                    if (error2) {
                        return resolve(error2)
                    }

                    console.log(stderr2)
                    console.log(stdout2)

                    return resolve(true)
                })
            })
        })

        function generateDeploymentSuffix() {
            return customAlphabet('1234567890abcdefghijklmnopqrstuvwxyz', 6)()
        }
    }

    function checkForDeployments() {
        console.log('Checking for deployments. (' + deployments.length + ')')

        for (let i=0; i<deployments.length; i++) {
            if (deployments[i].ready) {
                deploymentsQueue.push({
                    app: deployments[i].app,
                    releaseEvent: deployments[i].releaseEvent,
                    packageEvent: deployments[i].packageEvent
                })
                deployments[i].queued = true
                console.log('Deployment queue updated with ' + deployments[i].app.name + ':' + deployments[i].releaseEvent.release.tag_name)
            }
        }

        deployments = deployments.filter((d) => !d.queued)
    }

    function findApp(event) {
        const compare = (app) => app.name === event.repository.full_name
        const compare2 = (app) => event.package.package_version.package_url.includes(app.name)
        return event && event.repository && apps.some(compare)
            ? apps.find(compare)
            : event && event.package && apps.some(compare2)
                ? apps.find(compare2)
                : null
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
