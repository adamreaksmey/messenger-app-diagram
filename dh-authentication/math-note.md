

### 1️⃣ Key generation

Each side generates a key pair:

* **Private key**: a secret number, let's call it `a` for the client and `b` for the server.
* **Public key**: computed by multiplying the private key with a fixed base point on the curve. Let’s call the base point `G`.

So:

```
Client: public_key = a * G
Server: public_key = b * G
```

> `*` here is elliptic curve scalar multiplication, not normal multiplication.

---

### 2️⃣ Exchanging public keys

They exchange only the public keys:

* Client sends `A = a * G` to server
* Server sends `B = b * G` to client

Notice **the private keys `a` and `b` never leave their devices**.

---

### 3️⃣ Computing the shared secret

Now each side computes the shared secret:

* **Server computes:**

```
shared_secret = b * A = b * (a * G)
```

* **Client computes:**

```
shared_secret = a * B = a * (b * G)
```

---

### 4️⃣ Why it works

Elliptic curve scalar multiplication has this property:

```
b * (a * G) == a * (b * G)
```

So both sides get the **exact same point on the curve**, which becomes `shared_secret`.

* Server: `b * (a * G)`
* Client: `a * (b * G)`

✅ Result: identical shared secret on both sides.

---

### 5️⃣ Security

* **Private keys never travel** → eavesdropper only sees `A` and `B`.
* Without knowing `a` or `b`, it is computationally infeasible to compute `shared_secret` (this is the **Elliptic Curve Diffie-Hellman problem**, equivalent to the discrete log problem on elliptic curves).

---

So the **math guarantee** is simply:

```
shared_secret = private_key * peer_public_key = a*b*G = b*a*G
```