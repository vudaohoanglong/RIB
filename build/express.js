"use strict";
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g;
    return g = { next: verb(0), "throw": verb(1), "return": verb(2) }, typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
require("dotenv/config");
var tmp_promise_1 = require("tmp-promise");
var express_1 = __importDefault(require("express"));
var mongoose_1 = __importDefault(require("mongoose"));
var authRoutes_1 = __importDefault(require("./authRoutes"));
var passport_1 = __importDefault(require("passport"));
var passport_jwt_1 = __importDefault(require("passport-jwt"));
var passport_local_1 = require("passport-local");
var JWTStrategy = passport_jwt_1.default.Strategy, ExtractJwt = passport_jwt_1.default.ExtractJwt;
var bcrypt_1 = __importDefault(require("bcrypt"));
var User_1 = __importDefault(require("./models/User"));
var express_fileupload_1 = __importDefault(require("express-fileupload"));
var i18next_1 = __importDefault(require("i18next"));
var i18next_fs_backend_1 = __importDefault(require("i18next-fs-backend"));
var i18next_http_middleware_1 = __importDefault(require("i18next-http-middleware"));
var path_1 = __importDefault(require("path"));
var h5p_express_1 = require("@lumieducation/h5p-express");
var h5p_html_exporter_1 = __importDefault(require("@lumieducation/h5p-html-exporter"));
var H5P = __importStar(require("@lumieducation/h5p-server"));
var login_1 = __importDefault(require("./login"));
var startPageRenderer_1 = __importDefault(require("./startPageRenderer"));
var expressRoutes_1 = __importDefault(require("./expressRoutes"));
var User_2 = __importDefault(require("./User"));
var createH5PEditor_1 = __importDefault(require("./createH5PEditor"));
var utils_1 = require("./utils");
var config_js_1 = require("../config.js");
var tmpDir;
var start = function () { return __awaiter(void 0, void 0, void 0, function () {
    var useTempUploads, translationFunction, config, h5pEditor, h5pPlayer, server, htmlExporter, port;
    return __generator(this, function (_a) {
        switch (_a.label) {
            case 0:
                useTempUploads = process.env.TEMP_UPLOADS === 'true';
                if (!useTempUploads) return [3 /*break*/, 2];
                return [4 /*yield*/, (0, tmp_promise_1.dir)({ keep: false, unsafeCleanup: true })];
            case 1:
                tmpDir = _a.sent();
                _a.label = 2;
            case 2: return [4 /*yield*/, i18next_1.default
                    .use(i18next_fs_backend_1.default)
                    .use(i18next_http_middleware_1.default.LanguageDetector) // This will add the
                    // properties language and languages to the req object. See
                    // https://github.com/i18next/i18next-http-middleware#adding-own-detection-functionality
                    // how to detect language in your own fashion. You can also choose not
                    // to add a detector if you only want to use one language.
                    .init({
                    backend: {
                        loadPath: path_1.default.join(__dirname, '../node_modules/@lumieducation/h5p-server/build/assets/translations/{{ns}}/{{lng}}.json')
                    },
                    debug: process.env.DEBUG && process.env.DEBUG.includes('i18n'),
                    defaultNS: 'server',
                    fallbackLng: 'en',
                    ns: [
                        'client',
                        'copyright-semantics',
                        'hub',
                        'library-metadata',
                        'metadata-semantics',
                        'mongo-s3-content-storage',
                        's3-temporary-storage',
                        'server',
                        'storage-file-implementations'
                    ],
                    preload: ['en', 'de'] // If you don't use a language detector of
                    // i18next, you must preload all languages you want to use!
                })];
            case 3:
                translationFunction = _a.sent();
                return [4 /*yield*/, new H5P.H5PConfig(new H5P.fsImplementations.JsonStorage(path_1.default.join(__dirname, '../config.json'))).load()];
            case 4:
                config = _a.sent();
                return [4 /*yield*/, (0, createH5PEditor_1.default)(config, path_1.default.join(__dirname, '../h5p/libraries'), // the path on the local disc where
                    // libraries should be stored)
                    path_1.default.join(__dirname, '../h5p/content'), // the path on the local disc where content
                    // is stored. Only used / necessary if you use the local filesystem
                    // content storage class.
                    path_1.default.join(__dirname, '../h5p/temporary-storage'), // the path on the local disc
                    // where temporary files (uploads) should be stored. Only used /
                    // necessary if you use the local filesystem temporary storage class.,
                    path_1.default.join(__dirname, '../h5p/user-data'), function (key, language) { return translationFunction(key, { lng: language }); })];
            case 5:
                h5pEditor = _a.sent();
                h5pPlayer = new H5P.H5PPlayer(h5pEditor.libraryStorage, h5pEditor.contentStorage, config, undefined, undefined, function (key, language) { return translationFunction(key, { lng: language }); }, undefined, h5pEditor.contentUserDataStorage);
                server = (0, express_1.default)();
                return [4 /*yield*/, mongoose_1.default.connect(config_js_1.databaseURL, {})
                        .then(function () {
                        console.log('Connected to MongoDB');
                    })
                        .catch(function (err) {
                        console.error('Failed to connect to MongoDB:', err);
                    })];
            case 6:
                _a.sent();
                // Passport initialization
                passport_1.default.use(new passport_local_1.Strategy({
                    usernameField: 'email',
                    passwordField: 'password', // Tên trường chứa mật khẩu
                }, function (email, password, done) { return __awaiter(void 0, void 0, void 0, function () {
                    var user, isMatch, error_1;
                    return __generator(this, function (_a) {
                        switch (_a.label) {
                            case 0:
                                _a.trys.push([0, 3, , 4]);
                                return [4 /*yield*/, User_1.default.findOne({ email: email })];
                            case 1:
                                user = _a.sent();
                                // Kiểm tra người dùng có tồn tại không
                                if (!user) {
                                    return [2 /*return*/, done(null, false, { message: 'Người dùng không tồn tại' })];
                                }
                                return [4 /*yield*/, bcrypt_1.default.compare(password, user.password)];
                            case 2:
                                isMatch = _a.sent();
                                // Kiểm tra mật khẩu có khớp không
                                if (!isMatch) {
                                    return [2 /*return*/, done(null, false, { message: 'Mật khẩu không đúng' })];
                                }
                                // Xác thực thành công, trả về người dùng
                                return [2 /*return*/, done(null, user)];
                            case 3:
                                error_1 = _a.sent();
                                return [2 /*return*/, done(error_1)];
                            case 4: return [2 /*return*/];
                        }
                    });
                }); }));
                // Cấu hình Passport JWT Strategy
                passport_1.default.use(new JWTStrategy({
                    jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
                    secretOrKey: 'your_secret_key',
                }, function (jwtPayload, done) { return __awaiter(void 0, void 0, void 0, function () {
                    var user, error_2;
                    return __generator(this, function (_a) {
                        switch (_a.label) {
                            case 0:
                                _a.trys.push([0, 2, , 3]);
                                return [4 /*yield*/, User_1.default.findById(jwtPayload.id)];
                            case 1:
                                user = _a.sent();
                                // Kiểm tra người dùng có tồn tại không
                                if (!user) {
                                    return [2 /*return*/, done(null, false, { message: 'Người dùng không tồn tại' })];
                                }
                                // Xác thực thành công, trả về người dùng
                                return [2 /*return*/, done(null, user)];
                            case 2:
                                error_2 = _a.sent();
                                return [2 /*return*/, done(error_2)];
                            case 3: return [2 /*return*/];
                        }
                    });
                }); }));
                server.use(passport_1.default.initialize());
                server.use(express_1.default.json());
                server.use('/api', authRoutes_1.default);
                // Configure file uploads
                server.use((0, express_fileupload_1.default)({
                    limits: { fileSize: h5pEditor.config.maxTotalSize },
                    useTempFiles: useTempUploads,
                    tempFileDir: useTempUploads ? tmpDir === null || tmpDir === void 0 ? void 0 : tmpDir.path : undefined
                }));
                // delete temporary files left over from uploads
                if (useTempUploads) {
                    server.use(function (req, res, next) {
                        res.on('finish', function () { return __awaiter(void 0, void 0, void 0, function () { return __generator(this, function (_a) {
                            return [2 /*return*/, (0, utils_1.clearTempFiles)(req)];
                        }); }); });
                        next();
                    });
                }
                // It is important that you inject a user object into the request object!
                // The Express adapter below (H5P.adapters.express) expects the user
                // object to be present in requests.
                // In your real implementation you would create the object using sessions,
                // JSON webtokens or some other means.
                server.use(function (req, res, next) {
                    req.user = new User_2.default();
                    console.log(req.body);
                    console.log(req.headers['authorization']);
                    next();
                });
                // The i18nextExpressMiddleware injects the function t(...) into the req
                // object. This function must be there for the Express adapter
                // (H5P.adapters.express) to function properly.
                server.use(i18next_http_middleware_1.default.handle(i18next_1.default));
                // The Express adapter handles GET and POST requests to various H5P
                // endpoints. You can add an options object as a last parameter to configure
                // which endpoints you want to use. In this case we don't pass an options
                // object, which means we get all of them.
                server.use(h5pEditor.config.baseUrl, (0, h5p_express_1.h5pAjaxExpressRouter)(h5pEditor, path_1.default.resolve(path_1.default.join(__dirname, '../h5p/core')), // the path on the local disc where the
                // files of the JavaScript client of the player are stored
                path_1.default.resolve(path_1.default.join(__dirname, '../h5p/editor')), // the path on the local disc where the
                // files of the JavaScript client of the editor are stored
                undefined, 'auto' // You can change the language of the editor here by setting
                // the language code you need here. 'auto' means the route will try
                // to use the language detected by the i18next language detector.
                ));
                // The expressRoutes are routes that create pages for these actions:
                // - Creating new content
                // - Editing content
                // - Saving content
                // - Deleting content
                server.use(h5pEditor.config.baseUrl, (0, expressRoutes_1.default)(h5pEditor, h5pPlayer, 'auto' // You can change the language of the editor by setting
                // the language code you need here. 'auto' means the route will try
                // to use the language detected by the i18next language detector.
                ));
                // The LibraryAdministrationExpress routes are REST endpoints that offer
                // library management functionality.
                server.use("".concat(h5pEditor.config.baseUrl, "/libraries"), (0, h5p_express_1.libraryAdministrationExpressRouter)(h5pEditor));
                // The ContentTypeCacheExpress routes are REST endpoints that allow updating
                // the content type cache manually.
                server.use("".concat(h5pEditor.config.baseUrl, "/content-type-cache"), (0, h5p_express_1.contentTypeCacheExpressRouter)(h5pEditor.contentTypeCache));
                htmlExporter = new h5p_html_exporter_1.default(h5pEditor.libraryStorage, h5pEditor.contentStorage, h5pEditor.config, path_1.default.join(__dirname, '../h5p/core'), path_1.default.join(__dirname, '../h5p/editor'));
                server.get('/h5p/html/:contentId', function (req, res) { return __awaiter(void 0, void 0, void 0, function () {
                    var html;
                    var _a;
                    return __generator(this, function (_b) {
                        switch (_b.label) {
                            case 0: return [4 /*yield*/, htmlExporter.createSingleBundle(req.params.contentId, req.user, {
                                    language: (_a = req.language) !== null && _a !== void 0 ? _a : 'en',
                                    showLicenseButton: true
                                })];
                            case 1:
                                html = _b.sent();
                                res.setHeader('Content-disposition', "attachment; filename=".concat(req.params.contentId, ".html"));
                                res.status(200).send(html);
                                return [2 /*return*/];
                        }
                    });
                }); });
                // The startPageRenderer displays a list of content objects and shows
                // buttons to display, edit, delete and download existing content.
                server.get('/', function (req, res, next) {
                    res.redirect('/login');
                });
                server.get('/dashboard', (0, startPageRenderer_1.default)(h5pEditor));
                server.get('/login', (0, login_1.default)());
                server.use('/client', express_1.default.static(path_1.default.join(__dirname, 'client')));
                // We only include the whole node_modules directory for convenience. Don't
                // do this in a production app.
                server.use('/node_modules', express_1.default.static(path_1.default.join(__dirname, '../node_modules')));
                // Remove temporary directory on shutdown
                if (useTempUploads) {
                    [
                        'beforeExit',
                        'uncaughtException',
                        'unhandledRejection',
                        'SIGQUIT',
                        'SIGABRT',
                        'SIGSEGV',
                        'SIGTERM'
                    ].forEach(function (evt) {
                        return process.on(evt, function () { return __awaiter(void 0, void 0, void 0, function () {
                            return __generator(this, function (_a) {
                                switch (_a.label) {
                                    case 0: return [4 /*yield*/, (tmpDir === null || tmpDir === void 0 ? void 0 : tmpDir.cleanup())];
                                    case 1:
                                        _a.sent();
                                        tmpDir = null;
                                        return [2 /*return*/];
                                }
                            });
                        }); });
                    });
                }
                port = process.env.PORT || '8080';
                // For developer convenience we display a list of IPs, the server is running
                // on. You can then simply click on it in the terminal.
                (0, utils_1.displayIps)(port);
                server.listen(port);
                return [2 /*return*/];
        }
    });
}); };
// We can't use await outside a an async function, so we use the start()
// function as a workaround.
start();
//# sourceMappingURL=express.js.map