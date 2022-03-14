const bcrypt = require('bcryptjs');
const express = require("express");
const { body, validationResult } = require('express-validator');
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;

const mongoDb = "mongodb+srv://m001-student:1QcirL2wvvUwusv9@sandbox.cwhyp.mongodb.net/authentication_db_dev?retryWrites=true&w=majority";
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set("views", __dirname);
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));

// PASSPORT
/**
 * Finds a user in the User collection and tests if the password entered matches that in the collection
 */
passport.use(
    new LocalStrategy((username, password, done) => {
        User.findOne({ username: username }, (err, user) => {
            if (err) {
                return done(err);
            }
            if (!user) {
                return done(null, false, { message: "Incorrect username" });
            }
            bcrypt.compare(password, user.password, (err, res) => {
                if (res) {
                  // passwords match! log user in
                  return done(null, user)
                } else {
                  // passwords do not match!
                  return done(null, false, { message: "Incorrect password" })
                }
              });
        });
    })
);

passport.serializeUser(function(user, done) {
    done(null, user._id);
});

passport.deserializeUser(function(id, done) {
    User.findById(id, function(err, user) {
        done(err, user);
    });
});

app.use(passport.initialize());
app.use(passport.session());
/**
 * Allows accessing the current user in other middleware functions
 */
app.use(function(req, res, next) {
    res.locals.currentUser = req.user;
    next();
});

app.use(express.urlencoded({ extended: false }));

// GET
app.get("/", (req, res) => {
    res.render("index", { user: req.user });
});
app.get("/sign-up", (req, res) => res.render("sign-up-form"));
app.get("/log-out", (req, res) => {
    req.logout();
    res.redirect("/");
});

// POST
app.post("/sign-up", (req, res, next) => {
    //TODO: validate and sanitize later
    bcrypt.hash(req.body.password, 10, (err, hashedPassword) => {
        if (err) { return next(err);}
        const user = new User({
            username: req.body.username,
            password: hashedPassword,
        }).save(err => {
            if (err) {
                return next(err);
            }
            res.redirect("/");
        });
    })
});
app.post(
    "/log-in",
    passport.authenticate("local", {
        successRedirect: "/",
        failureRedirect: "/"
    })
);

app.listen(3000, () => console.log("app listening on port 3000!"));
