import express, { urlencoded }  from "express";
import path from "path"
import mongoose from "mongoose";
import cookieParser from "cookie-parser";
import jwt from "jsonwebtoken";
import bcrypt, { hash } from "bcrypt"

mongoose.connect("mongodb://127.0.0.1:27017", {
    dbName: "NodeJSAuth",
})
    .then(() => console.log("Databse connected"))
    .catch((e) => console.log(e));

const userschema = new mongoose.Schema({
    username: String,
    email: String,
    password: String,
});

// creating collection or model
const User = mongoose.model("users", userschema);

const PORT = 5000;

const app = express();

// Using MiddleWares
app.use(urlencoded({extended: true}));
app.use(express.static(path.join(path.resolve(), "public")));
app.use(cookieParser())

// Setting up view engine
app.set("view engine", "ejs");

const isAuthenticated = async (req, res, next) => {
    // console.log(req.cookies);       // npm i cookie-parser for display
    // req.cookies.token gives token value
    const {token} = req.cookies;
    if(token){

        const decoded = jwt.verify(token, "qwepoi");    //return user id 
        // (*req.user can be used in next handler, ie in '/' render*)
        req.user = await User.findById(decoded.userID); // contains user information
        // console.log(req.user);
        next();
    }
    else{
        res.redirect("/login");
    }

}
app.get("/", isAuthenticated, (req, res) => {
    // console.log(req.user.username);
    res.render("logout", {name : req.user.username });
})

app.get("/register", (req, res) => {
    res.render("register");
})

app.get("/login", (req, res) => {
    res.render("login");
})

app.get("/logout", (req, res) => {
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now()),      // expired now
    })
    res.redirect("/");
})

app.post("/register", async (req, res) => {
    const {name, email, password} = req.body;
    
    let user = await User.findOne({email});
    
    if(user){
        return res.redirect("/login");
    }

    const hashpassword= await bcrypt.hash("password", 10)
    
    const userdata = ({username: name, email: email, password: hashpassword});
    user = await User.create(userdata);

    // to create token and with recieved token we can decode token to get user id
    // use npm i jsonwebtoken
    const token = jwt.sign({userID: user._id}, "qwepoi", );

    res.cookie("token", token, {
        httpOnly: true,
        expires: new Date(Date.now() + (5 * 60 * 1000))
    })

    res.redirect("/");;
})

app.post("/login", async (req, res) => {

    const {email, password} = req.body;

    let user = await User.findOne({email});
    if(!user){
        return res.render("register");
    }

    const isMatch = await bcrypt.compare(password, user.password);           // npm i bcrypt for hiudding password in database
    if(!isMatch)    return res.render("login", ({email: email, message: "*Incorrect Password"}));

    const token = jwt.sign( {userID: user._id}, "qwepoi", );

    res.cookie("token", token , {
        httpOnly: true,
        // expires: new Date(Date.now()+ 3000),

    });

    res.redirect("/");
})


app.listen(PORT, () => {
    console.log("Server is Working");
})