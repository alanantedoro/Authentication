//jshint esversion:6
require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require("mongoose-findorcreate");

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
  password: String,
  googleId: String,
  secret: String
});

///     Adding the passport local mongoose to our userSchema. We are serilizing and deserializing our user so it put the config into our cookie and then broke it to know which user it is if he comebacks.
userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});


///     Google auth option
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

///     Routing
app.get("/", function(req, res){
  res.render("home");
});

app.get("/auth/google",
  passport.authenticate("google", {scope: ["profile"]})
);

app.get("/auth/google/secrets", 
  passport.authenticate("google", {failureRedirect: "/login"}),
  function(req, res){
    res.redirect("/secrets");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/secrets", function(req, res){
User.find({"secret": {$ne: null}}, function(err, foundUsers){
  if(err){
    console.log(err);
  } else{
    if (foundUsers){
      res.render("secrets", {usersWithSecrets: foundUsers});
    }
  }
});
});

app.get("/logout", function(req, res){
/// Deauth the user
req.logout();
res.redirect("/");  
})


app.get("/submit", function(req, res){
  if(req.isAuthenticated()){
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

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


app.post("/submit", function(req, res){
  const submittedSecret = req.body.secret;

  User.findById(req.user.id, function(err, foundUser){
    if(err){
      console.log(err);
    } else{
      if(foundUser){
        foundUser.secret = submittedSecret;
        foundUser.save(function(){
          res.redirect("/secrets")
        })
      }
    }
  })
});



app.listen(3000, function(){
  console.log("Server started on port 3000.");
});