//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");


const app = express();

app.use(express.static("public"));
app.set("view engine", "ejs");
app.use(bodyParser.urlencoded({extended:true}));

///     Initialize the session
app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false,
}));

///     Initialize Passport and tell the app to use the session package.
app.use(passport.initialize());
app.use(passport.session());

///     DB
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true, useUnifiedTopology: true});
mongoose.set("useCreateIndex", true);


const userSchema = new mongoose.Schema ({
  email: String,
  password: String
});

///     Adding the passport local mongoose to our userSchema. We are serilizing and deserializing our user so it put the config into our cookie and then broke it to know which user it is if he comebacks.
userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

///     Routing
app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
  /// Here we need to see if the user is already loged in or if it needs to.
  if(req.isAuthenticated()){
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
})

app.get("/logout", function(req, res){
/// Deauth the user
req.logout();
res.redirect("/");  
})

///     Encryption by hashing and salting

app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      console.log(err);
      res.redirect("/register")
    } else{
      passport.authenticate("local")(req, res, function(){ ///    If they ended up here we can send them to the secrets route
        res.redirect("/secrets");
      });
    }
  });

});




app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
});
///     Using passport to check if our user exist and authenticate him.
  req.login(user, function(err){
    if(err){
      console.log(err);
    } else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      });
  }
});
});





app.listen(3000, function(){
  console.log("Server started on port 3000.");
});