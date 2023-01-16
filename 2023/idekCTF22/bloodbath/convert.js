const convert = require("gd-level-to-json");
const fs = require("fs");

const data = fs.readFileSync("level.txt", "utf8");
const level = convert(data);

fs.writeFileSync("level.json", JSON.stringify(level, null, 2));