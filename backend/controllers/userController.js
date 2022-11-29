const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const asyncHandler = require("express-async-handler");
const User = require("../models/userModel");

// @desc    Register new user
// @route   POST /api/users
// @access  Public
const registerUser = asyncHandler(async (req, res) => {
    // asyncHandler use kora hoy .. exception handle korar jonno
    /**
     * jokhon amra ei endpoint e request send korbo .. tokhon request er body te kichu information ashbe
     *
     */
    const { name, email, password } = req.body;

    // little bit validation
    if (!name || !email || !password) {
        res.status(400); // bad request
        throw new Error("Please add all fields");
    }

    // Check if user exists
    const userExists = await User.findOne({ email }); // jei email ashse .. shei email diye jodi kono user
    // already exist kore ..

    if (userExists) {
        res.status(400);
        throw new Error("User already exists"); // ekta error pathabo
    }

    // Hash password
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    // Create user // user jehetu exist kore na .. finally amra user create korbo ..
    const user = await User.create({
        name,
        email,
        password: hashedPassword, // hashed password ta pass korbo
    });

    if (user) {
        res.status(201).json({
            // something is created .. // password kintu send korbo na ..
            _id: user.id, // create hoile .. ekta id paowa jabe ...
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(400);
        throw new Error("Invalid user data");
    }
});

// @desc    Authenticate a user
// @route   POST /api/users/login
// @access  Public
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    /**
     * jokhon amra ei endpoint e request send korbo .. tokhon request er body te kichu information ashbe
     */

    // Check for user email
    const user = await User.findOne({ email }); // email data base e khuje paowa jay kina .. check korbo

    if (user && (await bcrypt.compare(password, user.password))) {
        // user jodi khuje paowa jay and req.body er password er shathe jodi user er password er match kore
        // taile amra response e user er shob information pathabo .. tar shathe generateToken nam er
        // function er maddhome user er id pathiye .. token generate kore .. token send kore dibo ..

        res.json({
            _id: user.id,
            name: user.name,
            email: user.email,
            token: generateToken(user._id),
        });
    } else {
        res.status(400); // bad requst ..
        throw new Error("Invalid credentials");
    }
});

// @desc    Get user data
// @route   GET /api/users/me
// @access  Private
/**
 * login korar pore get me korbo .. so .. login korar pore front-end e token ta pathiye disi ..
 * sheta may be shekhan e request er headers e add hoye jabe .. bearer "token" ei format e ..
 *
 * tar por jokhon getMe call hobe .. mane she ekhon user er information jante chay .. tokhon amra
 * amader JWT secret diye token ta verify kore dekhbo .. thik thak thakle .. req.user er moddhe
 * user er information ta vore diye .. next() call kore dibo .. ei hocche kahini ..
 *  */
const getMe = asyncHandler(async (req, res) => {
    // protect middleware er moddhe req.user er moddhe user er informatio diye deowa hoyeche .. tai
    // ekhane access korte partesi ..
    res.status(200).json(req.user); // logged in user er shob information send korbo ..
    /// 😀
    // const { _id, name, email } = await User.findById(req.user.id);

    // res.status(200).json({
    //     id: _id,
    //     name,
    //     email,
    // });
});

// Generate JWT // token generate korte .. user er id ta lage .. ar JWT Secret ta lage .. option e
// expire time ta bole dite hoy ...
const generateToken = (id) => {
    return jwt.sign({ id }, process.env.JWT_SECRET, {
        expiresIn: "30d",
    });
};

module.exports = {
    registerUser,
    loginUser,
    getMe,
};
