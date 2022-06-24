import { h } from './misc.js'
import nacl from './nacl-fast-es.js'
import { decode, encode } from './base64.js'

let ws = new WebSocket("wss://"+location.host)

async function box (msg, dest, keys) {
  console.log(msg)
  console.log(dest)
  console.log(keys)
  const recp = decode(dest)
  const sender = decode(keys.substring(0, 44))
  const privatekey = decode(keys.substring(44))
  const nonce = nacl.randomBytes(nacl.box.nonceLength)
  const message = new TextEncoder().encode(msg)
  const boxed = nacl.box(message, nonce, recp, privatekey)
  const nonceMsg = new Uint8Array(sender.length + nonce.length + boxed.length)

  nonceMsg.set(sender)
  nonceMsg.set(nonce, sender.length)
  nonceMsg.set(boxed, sender.length + nonce.length)

  return nonceMsg
}

async function unbox (boxed, keys) {
  const privatekey = decode(keys.substring(44))
  const senderkey = boxed.slice(0, 32)
  console.log(encode(senderkey))
  const nonce = boxed.slice(32, 32 + 24)
  const msg = boxed.slice(32 + 24)

  const unboxed = nacl.box.open(msg, nonce, senderkey, privatekey)

  if (unboxed) {
    const message = new TextDecoder().decode(unboxed)
    return message
  }
}

async function genkey () {
  const genkey = nacl.box.keyPair()
  const key = encode(genkey.publicKey) + encode(genkey.secretKey)
  console.log(key)
  return key
}

//document.addEventListener('click', () => {
//  Notification.requestPermission() 
//})

genkey().then(key => {
  ws.onmessage = function (e) {
    const decoded = decode(e.data)
    unbox(decoded, key).then(unboxed => {
      const msg = h('div')
      if (unboxed) {
        msg.appendChild(h('span', [
          h('a', {href: '#' + encode(decoded.slice(0, 32))}, [e.data.substring(0,10) + '...']),
          ' > ' + unboxed
        ]))
        window.navigator.vibrate(200)
        //if (Notification.permission === "granted") {
        //  const notification = new Notification(unboxed)
        //}
      } else {
        msg.appendChild(h('span', [
          h('a', {href: '#' + encode(decoded.slice(0, 32))}, [encode(decoded.slice(0, 32)).substring(0, 10)]),
          '... > 🔒'
        ]))
      }
      if (screen.childNodes[1]) {
        screen.insertBefore(msg, screen.childNodes[1])
      } else {
        screen.appendChild(msg)
      }
    })
  }
  
  const screen = h('div')
  
  document.body.appendChild(screen)
  
  const keygen = h('span')
  
  keygen.appendChild(h('div', [
    h('a', {href: '#' + key.substring(0, 44)}, [key.substring(0, 44)]),
    ' (This is you)'
  ]))

  const input = h('input', {placeholder: 'Write something'})

  window.onhashchange = function () {
    input.placeholder = window.location.hash.substring(1)
  }
  
  const display = h('div', [keygen])

  const compose = h('div', {id: 'composer'}, [
    input,
    h('button', {onclick: function () {
      const dest = window.location.hash.substring(1)
      if (input.value && dest.length === 44) {
        box(input.value, dest, key).then(boxed => {
          ws.send(encode(boxed))
          input.value = ''
        })
      }
    }}, ['Send'])
  ])

  screen.appendChild(display) 
  screen.appendChild(compose)
})
