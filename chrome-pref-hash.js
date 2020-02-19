/*
references:
    https://www.adlice.com/google-chrome-secure-preferences/
    https://kaimi.io/2015/04/google-chrome-and-secure-preferences/
    https://habr.com/ru/post/438898/
    https://github.com/chromium/chromium/blob/master/services/preferences/tracked/pref_hash_calculator.cc
    https://github.com/chromium/chromium/blob/master/services/preferences/tracked/pref_hash_store_impl.cc
*/


const fs = require('fs')
const crypto = require('crypto')
// wmic useraccount get sid
const MACHINE_ID = 'S-1-5-21-4278753076-1478212823-788195486'
const FILE_INPUT = 'D:\\backup\\h\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Secure Preferences'
const FILE_OUTPUT = 'Secure Preferences'


const HMAC_SEED = Buffer.from([
    0xe7, 0x48, 0xf3, 0x36, 0xd8, 0x5e, 0xa5, 0xf9,
    0xdc, 0xdf, 0x25, 0xd8, 0xf3, 0x47, 0xa6, 0x5b,
    0x4c, 0xdf, 0x66, 0x76, 0x00, 0xf0, 0x2d, 0xf6,
    0x72, 0x4a, 0x2a, 0xf1, 0x8a, 0x21, 0x2d, 0x26,
    0xb7, 0x88, 0xa2, 0x50, 0x86, 0x91, 0x0c, 0xf3,
    0xa9, 0x03, 0x13, 0x69, 0x68, 0x71, 0xf3, 0xdc,
    0x05, 0x82, 0x37, 0x30, 0xc9, 0x1d, 0xf8, 0xba,
    0x5c, 0x4f, 0xd9, 0xc8, 0x84, 0xb5, 0x05, 0xa8])

const getObjectByPath = (obj, path) => path.split(".").reduce((o, key) => o && o[key] != null ? o[key] : null, obj)
let secPref = fs.readFileSync(FILE_INPUT)

// add @ before number keys to prevent changing the json order
// https://stackoverflow.com/questions/7214293/is-the-order-of-elements-in-a-json-list-preserved/11371866#11371866
secPref = secPref.toString().replace(/(?<=")\d+(?=":)/g, '@$&')
secPref = JSON.parse(secPref)

replaceMAC(secPref.protection.macs)
secPref.protection.super_mac = hash(MACHINE_ID + JSON.stringify(secPref.protection.macs))
fs.writeFileSync(FILE_OUTPUT, JSON.stringify(secPref).replace(/(?<=")@(?=\d+":)/g, '').replace(/</g, '\\u003C'))

function replaceMAC(obj, path = '') {
    Object.keys(obj).forEach((key) => {
        let currentPath = (path + (path ? '.' : '')) + key
        if (typeof obj[key] === 'string') {
            let tmp2 = getObjectByPath(secPref, currentPath)
            tmp = removeEmptyNode(tmp2)
            if ((tmp2 instanceof Array) && tmp === null) tmp = []
            let content = JSON.stringify(tmp)
            content = content === 'null' ? '' : content
            content = content.replace(/(?<=")@(?=\d+":)/g, '')
            content = content.replace(/</g, '\\u003C')
            
            let message = MACHINE_ID
            message += currentPath
            message += content
            
            // console.log(message)
            obj[key] = hash(message)
        } else {
            replaceMAC(obj[key], currentPath)
        }
    })
}

function isEmpty(obj) {
    if (obj === null || obj === undefined) {
        return true
    } else if (typeof obj === 'object') {
        return Object.keys(obj).length === 0
    } else {
        return false
    }
}

function removeEmptyNode(obj) {
    if (isEmpty(obj)) {
        return null
    } else if (typeof obj === 'object') {
        let tmp = JSON.parse(JSON.stringify(obj))
        Object.keys(tmp).forEach(key => {
            tmp[key] = removeEmptyNode(tmp[key])
            if (tmp[key] === null) delete tmp[key]
        })
        if (tmp instanceof Array) {
            tmp = tmp.filter(i => i != null)
        }
        if (isEmpty(tmp)) tmp = null
        return tmp
    } else {
        return obj
    }
}

function hash(message) {
    let hmac = crypto.createHmac('sha256', HMAC_SEED)
    hmac.update(Buffer.from(message))
    let result = hmac.digest('hex').toUpperCase()
    // if (message.match('blpcfgokakmgnkcojhhkbfbldkacnbeo')) console.log(message)
    return result
}
