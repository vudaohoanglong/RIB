"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.generateToken = exports.requireLogin = void 0;
var jsonwebtoken_1 = __importDefault(require("jsonwebtoken"));
function requireLogin(req, res, next) {
    if (req.cookies && req.cookies.token) {
        jsonwebtoken_1.default.verify(req.cookies.token, "privateKEY", function (err, decoded) {
            if (err) {
                return res.status(403).json({ message: 'Invalid token' });
            }
            req.userID = decoded._id.toString();
            req.permission = decoded.role;
            console.log(req.userID, req.permission);
        });
        next();
    }
    else {
        res.redirect('/login');
    }
}
exports.requireLogin = requireLogin;
function generateToken(payload) {
    try {
        return jsonwebtoken_1.default.sign(payload, "privateKEY");
    }
    catch (error) {
        console.log("Error in generate access token:  + ".concat(error));
        return null;
    }
}
exports.generateToken = generateToken;
//# sourceMappingURL=auth.js.map