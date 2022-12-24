// cbor.js
// import cbor-js
var fingerArr = {
    "7" : "Left Index Finger",
    "8" : "Left Middle Finger",
    "9" : "Left Ring Finger",
    "10" : "Left Little Finger",
    "6" : "Left Thumb",
    "2" : "Right Index Finger",
    "3" : "Right Middle Finger",
    "4" : "Right Ring Finger",
    "5" : "Right Little Finger",
    "1": "Right Thumb",
};
function runCode() {
    var data = cborToJson(document.getElementById('qr_code').value)
    console.log(data)
}

function signaturecheck() {
 //
 var data = cborToJson(document.getElementById('qr_code').value, true)
    console.log(data)
}

/// THIS IS THE THING YOU WANT
function cborToJson(qr_string, signaturecheck) {
    if (typeof signaturecheck == undefined) {
        signature = false;
    }

    console.log('INPUT', qr_string)
    //Remove the app deeplink from the QR. First 4 characters in the QR should say what app it should open on a mobiel phone
    var string = String(qr_string).slice(4);
    console.log('var string', string)
    
    //Decode the base45 data.
    let base45Decoded = decode(string);
    console.log('base45Decoded', base45Decoded)
    
    //Convert to final processable buffer
    let rawToUi8 = convertArrayToUintArray(base45Decoded.raw);
    console.log('rawToUi8', rawToUi8)
    var unzipped = typedArrayToBuffer(rawToUi8);
    console.log('unzipped', unzipped)
    
    //Chk CWT. How to verify signature? 
    console.log('CWT', CBOR.decode(unzipped))
    // [headers, headers2, payload, signature] = CBOR.decode(unzipped);
    let d = CBOR.decode(unzipped);
    headers1 = d[0]
    headers2 = d[1]
    payload = d[2]
    signature = d[3]
    console.log('SIGN',btoa(Uint8ToString(signature)));

    
    //Get the claim
    claim = CBOR.decode(typedArrayToBuffer(payload));
    console.log('claim', claim)
    
    if (signaturecheck) {
        console.log(formatVersion1(claim['169']))
        verify(formatVersion1(claim['169']), btoa(Uint8ToString(signature)))
        return
    }
    //This is an errror
    if (claim["1"] != "PH") {
        return false;
        // console.error("not issued by Philsys");
    }

    let final_credential_map = claim["169"];

    let image = final_credential_map.img;
    console.log('image', image)
    var u8 = new Uint8Array(image);
    console.log('u8', u8)
    var b64encoded = btoa(Uint8ToString(u8));
    console.log('b64encoded', b64encoded)

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

/////// base45
const BASE45_CHARSET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:"
var fromCharCode = function fromCharCode(c) {
    return BASE45_CHARSET.charAt(c);
};

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


// var EdDSA = require(['elliptic']);
//         global.window.EdDSA = EdDSA
function verifyEddsa(msg, sig){            
    var ec = new EdDSA('ed25519');
    var pk64 = 'vD3czlgHEpf2sxGcri6iTm4zeEEA+jfd9tTq9S8zxe8='
    var key = ec.keyFromPublic(base64ToHex(pk64), 'hex');
    var b64payload = btoa(String(msg));
    var hexPayload = base64ToHex(b64payload);
    var hexSig = base64ToHex(sig)
    var state = key.verify(hexPayload, hexSig);
    if (!state){
        pushStatus("TAMPERED");
    }
    return state
}
function verify(qrMsg, qrSignature) {
    // let genPublicKey = `gU5ZsBIH3A1eUA/zJfcF91nmDEMuaTH41/ng8bzgzWQ=`;
    var genPublicKey = 'vD3czlgHEpf2sxGcri6iTm4zeEEA+jfd9tTq9S8zxe8='
    var publicKey = nacl.util.decodeBase64(genPublicKey);
    
    let signature = null;
    let verifiedMsg = null;
    try {
        signature = nacl.util.decodeBase64(qrSignature);
        msg = nacl.util.decodeUTF8(qrMsg);
        verifiedMsg = nacl.sign.detached.verify(msg, signature, publicKey);
    } catch (err) {
        console.log(err);
        return false;
    }
    console.log('verifiedMsg', verifiedMsg)
    return verifiedMsg;
}

/// EDDSA related decoding

// claim[169]
function formatVersion1(qrJson) {
    var payloadString = "{\n" + "  \"DateIssued\": \""+qrJson.d+"\",\n" + "  \"Issuer\": \""+qrJson.i+"\",\n" + "  \"subject\": {\n" +
        "    \"Suffix\": \""+qrJson.sb.sf+"\",\n" + "    \"lName\": \""+qrJson.sb.ln+"\",\n" + "    \"fName\": \""+qrJson.sb.fn+"\",\n" + "    \"mName\": \""+qrJson.sb.mn+"\",\n"
            + "    \"sex\": \""+qrJson.sb.s+"\",\n" + "    \"BF\": \""+qrJson.sb.BF+"\",\n"
            + "    \"DOB\": \""+qrJson.sb.DOB+"\",\n" + "    \"POB\": \""+qrJson.sb.POB+"\",\n"
            + "    \"PCN\": \""+qrJson.sb.PCN+"\"\n" + "  },\n" + "  \"alg\": \""+/*qrJson.alg*/ 'EDDSA' +"\"\n" + "}";
    return payloadString;
}