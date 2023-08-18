const express = require("express");
const morgan = require("morgan");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const mongosanitize = require("express-mongo-sanitize");
const xss = require("xss-clean");
const bodyParser = require("body-parser"); //
const cors = require("cors");
const cookieParser = require("cookie-parser");
const session = require("cookie-session");

const app = express();

app.use(
  cors({
    origin: "*",
    methods: ["GET", "PATCH", "POST", "DELETE", "PUT"],
    credentials: true,
  })
);
app.use(cookieParser());
app.use(express.json({ limit: "10kb" }));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(
  session({
    secret: "keyboard cat",
    proxy: true,
    resave: true,
    saveUnintialized: true,
    cookie: {
      secure: false,
    },
  })
);
app.use(helmet());

if (process.env.NODE_ENV === "development") {
  app.use(morgan("dev"));
}

const limiter = rateLimit({
  max: 3000,
  windowMs: 60 * 60 * 1000, // In one hour
  message:
    "Trop de requêtes émise depuis cette adresse IP. Merci de réessayer dans une heure environ!",
});

app.use("chat-app", limiter);

app.use(
  express.urlencoded({
    extended: true,
  })
);
app.use(mongosanitize());
app.use(xss());

app.get("/", () => "api");
app.use("/api/auth", require("./routes/authRoutes"));

module.exports = app;
