import express from "express";
import path from "path";
import cookieParser from "cookie-parser";
import mongoose from "mongoose";
import jwt from  "jsonwebtoken";
import bcrypt from "bcrypt";
const app = express();
//http only access in client side
// Middleware to parse cookies and form data
app.use(cookieParser());
app.use(express.urlencoded({ extended: true }));
// Serve static files
app.use(express.static(path.join(path.resolve(), "./public")));
// Set the view engine to EJS
app.set("view engine", "ejs");
// Route to render the login page
app.get("/login", (req, res) => {
    res.render("login");
});
// Middleware to check if the user is authenticated
//jwt token website me jaake check hojayega decoding ke liye
//bcrypt se password nhi dikhta hai db me
const isAuthenticated = async(req, res, next) => {
    const { token } = req.cookies;
    if (token) {
        const decoded=jwt.verify(token,"sxncjcedmecie");
        req.user=await User.findById(decoded._id)
        next();
    } else {
        res.redirect("/login");
    }
};
// Route to render the home page (logout page if authenticated)
app.get("/", isAuthenticated, (req, res) => {
    res.render("logout",{name:req.user.name});
});
app.get("/register", (req, res) => {
    res.render("register");
});
app.get("/login", (req, res) => {
    res.render("login");
});
app.post("/login",async(req, res) => {
    const { email, password } = req.body;
    let user=await User.findOne({email});
    if(!user)
    {
        return res.redirect("/register");
    }
    const ismatch=await bcrypt.compare(password,user.password);
   if(!ismatch)
    return res.render("login",{email,message:"Incorrect Password"});
   const token=jwt.sign({_id:user._id},"sxncjcedmecie");
   // Set a cookie with the user's ID as the token
   res.cookie("token",token, {
       httpOnly: true,
       expires: new Date(Date.now() + 60 * 1000), // 1 minute expiry
   });
   res.redirect("/");

});
// POST route for login and user creation
app.post("/register", async (req, res) => {
    const { name, email,password} = req.body;
    //to find single user'
    let user = await User.findOne({email});
    // Create a new user in the database
    if(user)
    {
        return res.redirect("/login");
    }
    const hashedpassword=await bcrypt.hash(password,10);
    user = await User.create({ name, email,password:hashedpassword,});
    const token=jwt.sign({_id:user._id},"sxncjcedmecie");
    // Set a cookie with the user's ID as the token
    res.cookie("token",token, {
        httpOnly: true,
        expires: new Date(Date.now() + 60 * 1000), // 1 minute expiry
    });
    res.redirect("/");
});
// MongoDB connection
mongoose.connect("mongodb://localhost:27017", {
    dbName: "backend",
})
.then(() => console.log("Database connected"))
.catch((e) => console.log(e));
// Define the user schema and model
const userSchema = new mongoose.Schema({
    name: String,
    email: String,
    password:String,
});
const User = mongoose.model("User", userSchema);
// Route to handle logout
app.get("/logout", (req, res) => {
    // Clear the cookie by setting its value to null and expiry to now
    res.cookie("token", null, {
        httpOnly: true,
        expires: new Date(Date.now()),
    });
    res.redirect("/login");
});
// Start the server
app.listen(5000, () => {
    console.log("Server is running on port 5000");
});
