const fs = require("fs");

exports.parsePrivate = () => {
    const pem = fs.readFileSync("server.pem").toString();
    const arr = pem.split("-----").filter(v => {
        if (v) {
            if (v === "\n") return false;
            return true;
        }
        return false;
    });
    const key1 = arr.slice(0, 2);
    const key2 = arr.slice(3, 5);

    const beginHeader = "BEGIN PRIVATE KEY";
    const endFooter = "END PRIVATE KEY";

    let key = "";
    if (key1[0] === beginHeader) [, key] = key1;
    else [, key] = key2;

    return `-----${beginHeader}-----${key}-----${endFooter}-----`;
};

exports.parseCert = () => {
    const pem = fs.readFileSync("server.pem").toString();
    const arr = pem.split("-----").filter(v => {
        if (v) {
            if (v === "\n") return false;
            return true;
        }
        return false;
    });
    const key1 = arr.slice(0, 3);
    const key2 = arr.slice(3, 6);

    const beginHeader = "BEGIN CERTIFICATE";
    const endFooter = "END CERTIFICATE";

    let key = "";
    if (key1[0] === beginHeader) [, key] = key1;
    else [, key] = key2;

    return `-----${beginHeader}-----${key}-----${endFooter}-----`;
};
