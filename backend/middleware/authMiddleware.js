const jwt = require("jsonwebtoken");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");
/**
 * now we want to be able to protect routes.. eta amra custom middleware er maddhome kore thaki ..
 * routes file e use korbo ei middleware ..
 */

const protect = asyncHandler(async (req, res, next) => {
    let token;

    if (
        req.headers.authorization && // request er headers e token ta ashbe ..
        req.headers.authorization.startsWith("Bearer")
    ) {
        try {
            // Get token from bearer header
            token = req.headers.authorization.split(" ")[1]; // " " diye split korle .. array te shift hobe
            // shetar 1 number index e token ta thake.. 0 number index e bearer word ta thake

            // Verify token
            const decoded = jwt.verify(token, process.env.JWT_SECRET);

            // Get user from the token // token has userId as payload .. when we generate token .. we give
            // id of user who want to log in or register ..
            req.user = await User.findById(decoded.id).select("-password"); // joto gula route protected
            // decoded.id .. eta karon generate token er moddhe amra id pass korechilam .. shekhan e amra
            // onek kichui send korte pari .. shegula amra ekhane pabo .. name o send korte pari ..
            // shob jaygay req.user er moddhe user er information ta pabo .. amra hashed password chai na ..
            // tai password er age ekta minus diye nilam ..  password include hobe na ..

            next(); // next middleware call korbo
        } catch (error) {
            console.log(error);
            res.status(401); // 401 mane holo not authorized ...
            throw new Error("Not authorized"); // Error throw kortesi ..
        }
    }

    if (!token) {
        res.status(401);
        throw new Error("Not authorized, no token");
    }
});

module.exports = { protect };
