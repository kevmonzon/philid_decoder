// cbor.js
// import cbor-js

function runCode() {
    var data = cborToJson(document.getElementById('qr_code').value)
    console.log(data)
}

/// THIS IS THE THING YOU WANT
function cborToJson(qr_string) {
    //Remove the app deeplink from the QR. First 4 characters in the QR should say what app it should open on a mobiel phone
    var string = String(qr_string).slice(4);

    //Decode the base45 data.
    let base45Decoded = decode(string);

    //Convert to final processable buffer
    let rawToUi8 = convertArrayToUintArray(base45Decoded.raw);
    var unzipped = typedArrayToBuffer(rawToUi8);

    //Chk CWT. How to verify signature? 
    [headers1, headers2, payload, signature] = CBOR.decode(unzipped);

    //Get the claim
    claim = CBOR.decode(typedArrayToBuffer(payload));

    //This is an errror
    if (claim["1"] != "PH") {
        return false;
        // console.error("not issued by Philsys");
    }

    let final_credential_map = claim["169"];

    let image = final_credential_map.img;
    var u8 = new Uint8Array(image);
    var b64encoded = btoa(Uint8ToString(u8));

    final_credential_map.img = b64encoded;
    return final_credential_map;
}

function convertArrayToUintArray(array) {
    COSE = buf2hex(array);
    var typedArray = new Uint8Array(COSE.match(/[\da-f]{2}/gi).map(function (h) {
        return parseInt(h, 16)
    }))
    return typedArray;
}

//Convert the given buffer to hex
function buf2hex(buffer) {
    var u = new Uint8Array(buffer),
        a = new Array(u.length),
        i = u.length;
    while (i--) // map to hex
        a[i] = (u[i] < 16 ? '0' : '') + u[i].toString(16);
    u = null; // free memory
    return a.join('');
};

//Slice the typed array to just the buffer
function typedArrayToBuffer(array) {
    return array.buffer.slice(array.byteOffset, array.byteLength + array.byteOffset)
}

function Uint8ToString(u8a) {
    var CHUNK_SZ = 0x8000;
    var c = [];
    for (var i = 0; i < u8a.length; i += CHUNK_SZ) {
        c.push(String.fromCharCode.apply(null, u8a.subarray(i, i + CHUNK_SZ)));
    }
    return c.join("");
}

// base45
function encode(uint8array) {
    var output = [];

    for (var i = 0, length = uint8array.length; i < length; i += 2) {
        if (uint8array.length - i > 1) {
            var x = (uint8array[i] << 8) + uint8array[i + 1]
            var [e, x] = divmod(x, 45 * 45)
            var [d, c] = divmod(x, 45)
            output.push(fromCharCode(c) + fromCharCode(d) + fromCharCode(e))
        } else {
            var x = uint8array[i]
            var [d, c] = divmod(x, 45)
            output.push(fromCharCode(c) + fromCharCode(d))
        }
    }
    return output.join('')
};

var divmod = function divmod(a, b) {
    var remainder = a
    var quotient = 0
    if (a >= b) {
        remainder = a % b
        quotient = (a - remainder) / b
    }
    return [quotient, remainder]
}

const BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
var fromCharCode = function fromCharCode(c) {
    return BASE45_CHARSET.charAt(c);
};

function decode(str) {
    var output = []
    var buf = []

    for (var i = 0, length = str.length; i < length; i++) {
        //console.log(i);    
        var j = BASE45_CHARSET.indexOf(str[i])
        if (j < 0)
            console.log('Base45 decode: unknown character n.', i, j);
        //throw new Error('Base45 decode: unknown character');
        buf.push(j)
    }

    for (var i = 0, length = buf.length; i < length; i += 3) {
        var x = buf[i] + buf[i + 1] * 45
        if (length - i >= 3) {
            var [d, c] = divmod(x + buf[i + 2] * 45 * 45, 256)
            output.push(d)
            output.push(c)
        } else {
            output.push(x)
        }
    }
    var enc = new TextEncoder();
    return { "enc": enc.encode(output), "raw": output };
    //return Buffer.from(output);
};
