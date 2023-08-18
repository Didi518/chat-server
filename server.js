const app = require("./app");
const http = require("http");
const dotenv = require("dotenv");
const mongoose = require("mongoose");

process.on("uncaughtException", (err) => {
  console.log(err);
  process.exit(1);
});

const server = http.createServer(app);

dotenv.config({ path: "./config.env" });

const DB = process.env.DB_URI.replace("<PASSWORD>", process.env.DB_PASSWORD);
mongoose
  .set("strictQuery", false)
  .connect(DB, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("connecté sur mongo");
  })
  .catch((err) => {
    console.log(err);
  });

const port = process.env.PORT || 8000;

server.listen(port, () => {
  console.log(`Serveur connecté sur le port: ${port}`);
});

process.on("unhandledRejection", (err) => {
  console.log(err);
  server.close(() => {
    process.exit(1);
  });
});
