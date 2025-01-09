const bodyParser = require("body-parser");
const express = require("express");
const mongoose = require("mongoose");
const app = express();
const mongourl = "mongodb://127.0.0.1:27017/assignment2";
const User = require("./models/user");
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const saltRounds = 10;
const jwtSecret="mySecretKey";

app.use(bodyParser.json());

mongoose.connect(mongourl)
    .then(() => {
        console.log("connected")
    })
    .catch((error) => {
        console.log(error)
    })

app.listen(3000, () => {
    console.log("listening on port 3000")
})

app.get('/home', (req, res) => {
    res.send("Welcome Home")
})

app.get('/about', (req, res) => {
    res.send("I'm Shajia")
})

app.get('/user/:userid', (req, res) => {
    const id = req.params.userid;
    res.send(id)
})

app.post('/api/signup', async (req, res) => {
    const username = req.body.username;
    const email = req.body.email;
    const password = req.body.password;
    bcrypt.hash(password, saltRounds, async (err, hash) => {
        const user = new User({ username, email, password })
        user.password = hash;
        try {
            await user.save();
            res.status(201).json({
                user
            })
        }
        catch (error) {
            res.status(400).json({
                error: error.message
            })
        }
    });
})

app.post('/api/login', async (req, res) => {
    const email = req.body.email;
    const pwd = req.body.password;
    console.log(email, " ", pwd);
    var user = await User.findOne({ email });
    console.log(user);
    if (user!=null && user!==undefined) {
        if(pwd!==undefined && pwd!==''){
            bcrypt.compare(pwd, user.password, function (err, result) {
                if (result == true) {
                    const token = jwt.sign(
                        { userId: user._id, email: user.email },
                        jwtSecret,
                        { expiresIn: '1h' }
                    );
                    res.status(200).json({ message: 'Sign-in successful', token });                }
                else {
                    res.status(201).json("incorrect password");
                }
            });
        }
            else { res.status(201).json("incorrect password"); }
    }
    else { res.status(201).json("user not found"); }
})

//protected route handler
const protectedRoute = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ message: 'No token provided' });
    }
    const token = authHeader.split(' ')[1];
    jwt.verify(token, jwtSecret, (err, decoded) => {
        if (err) {
            return res.status(401).json({ message: 'Invalid token' });
        }
        req.user = decoded;
        next();
    });
}
app.get('/api/protected', protectedRoute, (req, res) => {
    res.status(200).json({ message: 'Access to protected route granted', user: req.user });
});
