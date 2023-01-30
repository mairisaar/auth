//Level 1 - username and password only
//Level 2 - encryption
//Level 3 - hashing passwords
//Level 4 - salting and hashing passwords with bcrypt
//Level 5 - cookies and sessions
//Level 6 - OAuth 2.0

require('dotenv').config();
const express = require("express");
const ejs = require("ejs");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");

const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

app.use(session({
  secret: "Our little secret.",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect('mongodb://127.0.0.1:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});

userSchema.plugin(passportLocalMongoose);

const User = new mongoose.model("User", userSchema);

passport.use(User.createStrategy());

passport.serializeUser(User.serializeUser());
passport.deserializeUser(User.deserializeUser());

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/logout", function(req, res, next){
  req.logout(function(err) {
      if (err) { return next(err); }
      res.redirect("/");
    });
});

app.get("/secrets", function(req, res){
  if(req.isAuthenticated()){
    res.render("secrets");
  }else{
    res.redirect("/login")
  }
});


app.post("/register", function(req, res){

  User.register({username: req.body.username}, req.body.password, function(err, user){
    if(err){
      log(err);
      res.redirect("/register");
    }else{
      passport.authenticate("local")(req, res, function(){
        res.redirect("/secrets");
      })
    }
  });

});

app.post("/login", function(req, res){

  const user = new User({
    username: req.body.username,
    password: req.body.password
  });

  req.login(user, function(err){
    if(err){
      console.log(err);
    }else{
      passport.authenticate("local")(req, res, function(){
        res.render("secrets");
      });
    }
  });
});



app.listen(3000, function(){
  console.log("Server is listening on port 3000.");
});
