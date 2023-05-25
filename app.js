const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const bycript = require("bcryptjs");
const mongoose = require("mongoose");
const flash = require("connect-flash");
const Schema = mongoose.Schema;
require("dotenv").config();

const mongoDb = process.env.mongoUrl;
mongoose.connect(mongoDb);
const db = mongoose.connection;
db.on("error", () => console.error("mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true },
  })
);

const app = express();
app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");
app.use(flash());

passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      const passwordMatchesTheHashedPass = await bycript.compare(
        password,
        user.password
      );

      if (!passwordMatchesTheHashedPass) {
        return done(null, false, { message: "Incorrect password" });
      }
      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);

passport.serializeUser(function (user, done) {
  done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use((req, res, next) => {
  res.locals.currentUser = req.user;
  next();
});

app.get("/", (req, res) => {
  const errorMessages = req.flash("error");

  res.render("index", { errorMessages: errorMessages });
});

app.get("/sign-up", (req, res) => res.render("sign_up_form"));
app.post("/sign-up", async (req, res, next) => {
  try {
    const { username, password } = req.body;
    const hashedPassword = await bycript.hash(password, 10);

    const user = new User({
      username: username,
      password: hashedPassword,
    });

    const result = await user.save();
    req.login(user,(err)=>{
      if(err){
        res.status(401).send('User not authenticated');
      }else{
        res.redirect('/')
      }
    })
  } catch (err) {
    return next(err);
  }
});

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/",
    failureFlash: true,
  })
);

app.post("/log-out", (req, res, next) => {
  req.logOut((err) => {
    if (err) {
      return next(err);
    }
    res.redirect("/");
  });
});

app.listen(3000, () => console.log("app listening on port 3000!"));
