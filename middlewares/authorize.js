const jwt = require("jsonwebtoken");

exports.identifier = (req, res, next) => {
    let token;
    if(req.headers.client === 'not-browser') {
        token = req.headers.authorization;
    } else {
        token = req.cookies('Authorization')
    }

    if(!token) {
        return res.status(403).json({success: false})
    }
}