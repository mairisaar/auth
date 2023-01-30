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
const bcrypt = require("bcrypt");
const saltRounds = 10;

const app = express();

app.use(express.static("public"));
app.use(bodyParser.urlencoded({extended: true}));
app.set("view engine", "ejs");

mongoose.connect('mongodb://127.0.0.1:27017/userDB');

const userSchema = new mongoose.Schema({
  email: String,
  password: String
});


const User = new mongoose.model("User", userSchema);

app.get("/", function(req, res){
  res.render("home");
});

app.get("/login", function(req, res){
  res.render("login");
});

app.get("/register", function(req, res){
  res.render("register");
});

app.get("/logout", function(req, res){
  res.redirect("/");
});

app.post("/register", function(req, res){

  bcrypt.hash(req.body.password, saltRounds, function(err, hash) {
    const newUser = new User({
      email: req.body.username,
      password: hash
    });

    newUser.save(function(err){
      if(err){
        console.log(err);
      }else{
        res.render("secrets");
      }
    });
  });

});

app.post("/login", function(req, res){

  User.findOne({email: req.body.username}, function(err, foundUser){
    if(err){
      console.log(err);
    }else{
      if(foundUser){
        bcrypt.compare(req.body.password, foundUser.password, function(err, result) {
          res.render("secrets");
        });
      }
    }
  });
});




app.listen(3000, function(){
  console.log("Server is listening on port 3000.");
});
