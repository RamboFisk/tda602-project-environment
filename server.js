const express = require("express");
const handlebars = require("handlebars");
const Cookies = require("cookies");
const subdomain = require("express-subdomain")

const fs = require("fs");
const path = require("path");
const util = require("util");

const PORT = 8080;

const app = express();

const staticRouter = express.Router();
staticRouter.use(express.static('static'));
app.use("/static", staticRouter);

// Utilities
function readFile(filePath, acceptNoFile) {
    filePath = path.join(__dirname, filePath);
    return new Promise((resolve, reject) => {
        fs.readFile(filePath, "utf8", (error, content) => {
            if(error) {
                if(error.code === "ENOENT" && acceptNoFile) {
                    resolve("");
                }
                else {
                    reject(error);
                }
            }
            else {
                resolve(content);
            }
        });
    });
}
async function getExplList() {
    const filePath = path.join(__dirname, "expl");
    const files = await util.promisify(fs.readdir)(filePath);
    const explList = {};
    for(var i in files) {
        const file = files[i];
        const currentFile = path.join(__dirname, "expl", file);
        const stat = await util.promisify(fs.stat)(currentFile);
        if(stat.isDirectory()) {
            explList[file] = {};
        }
    }
    return explList;
}
async function sendHandlebars(res, templatePath, variables) {
    const fileContent = await readFile(templatePath);
    const template = handlebars.compile(fileContent);
    const content = template(variables);

    res.status(200);
    res.set("Content-Type", "text/html");
    res.end(content);
}
async function sendUntrusted(req, res, templatePath) {
    const expl = req.params.expl;
    const elements = await readFile(`expl/${expl}/untrusted.html`, true);
    const trustedElements = await readFile(`expl/${expl}/trusted.html`, true);
    const code = await readFile(`expl/${expl}/untrusted.js`);

    await sendHandlebars(res, templatePath, {
        expl,
        elements,
        code,
        trustedElements,
    });
}

// Middleware for asynchronous calls
const asyncMiddleware = fn => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

// Bad domain
const badRouter = express.Router();
badRouter.get("/steal-cookie.jpg", (req, res) => {
    console.log(`Successfully leaked the cookie(s) ${req.query.cookie}`);
    res.end();
});
app.use(subdomain("bad", badRouter));

// Cookies
app.use(Cookies.express());
app.use("/", (req, res, next) => {
    res.cookies.set("time-" + req.url, new Date().toString(), {
        httpOnly: false,
    });
    next();
});

// Unsafe
app.get("/:expl/unsafe", asyncMiddleware(async (req, res) => {
    await sendUntrusted(req, res, "env/unsafe/index.html");
}));

// CSP
app.get("/:expl/csp", asyncMiddleware(async (req, res, next) => {
    res.set("Content-Security-Policy", "default-src 'self'");
    await sendUntrusted(req, res, "env/csp/index.html");
}));
app.get("/:expl/csp/script.js", asyncMiddleware(async (req, res, next) => {
    const expl = req.params.expl;
    const content = await readFile(`expl/${expl}/untrusted.js`);

    res.status(200);
    res.set("Content-Type", "application/javascript");
    res.end(content);
}));

// Iframe
app.get("/:expl/iframe", asyncMiddleware(async (req, res) => {
    const expl = req.params.expl;
    const trustedElements = await readFile(`expl/${expl}/trusted.html`, true);
    await sendHandlebars(res, "env/iframe/outer.html", {
        expl,
        trustedElements,
    });
}));
app.get("/:expl/iframe/inner", asyncMiddleware(async (req, res) => {
    await sendUntrusted(req, res, "env/iframe/inner.html");
}));

// Caja
app.get("/:expl/caja", asyncMiddleware(async (req, res) => {
    const expl = req.params.expl;
    const trustedElements = await readFile(`expl/${expl}/trusted.html`, true);
    await sendHandlebars(res, "env/caja/outer.html", {
        expl,
        trustedElements,
    });
}));
app.get("/:expl/caja/inner", asyncMiddleware(async (req, res) => {
    await sendUntrusted(req, res, "env/caja/inner.html");
}));

// adsafe
app.get("/:expl/adsafe", asyncMiddleware(async (req, res) => {
    const expl = req.params.expl;
    const trustedElements = await readFile(`expl/${expl}/trusted.html`, true);
    const elements = await readFile(`expl/${expl}/untrusted.html`, true);
    const code = await readFile(`expl/${expl}/untrusted.js`);

    await sendHandlebars(res, "env/adsafe/index.html", {
        expl,
        elements,
        code,
        trustedElements,
    });
}));

// Details
app.get("/:expl", asyncMiddleware(async (req, res) => {
    await sendHandlebars(res, "expl/index.html", {
        expl: req.params.expl,
        env: {
            unsafe: {},
            iframe: {},
            caja: {},
            csp: {},
            adsafe: {},
        },
    });
}));

// Index
app.get("/", asyncMiddleware(async (req, res) => {
    const expl = await getExplList();
    await sendHandlebars(res, "env/index.html", {
        expl,
    });
}));

// Catch invalid URLs
app.all("/*", (req, res) => {
    res.status(404);
    res.set("Content-Type", "text/html");
    res.end("<h1>404 - Not found</h1>");
});

// Error handling
app.use((prev, req, res, next) => {
    res.status(500);
    res.set("Content-Type", "text/html");
    res.end("<h1>500 - Internal server error</h1><p>" + prev.stack + "</p>");
});

// Start the server
app.listen(PORT, "localhost.net", () => {
    console.log(`Demo environment running on http://localhost.net:${PORT} and http://bad.localhost.net:${PORT}`);
});
