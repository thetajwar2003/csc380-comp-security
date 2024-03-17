# Computer Security Project 1 – CCA2 Hybrid Encryption

## Members: Furqan Khan, Mohammed Mamun, and Tajwar Rahman

## _Due:_ Tuesday, March 12th @ 11:59pm

## Synopsis

In this assignment you are asked to build a public key cryptosystem using a _key encapsulation mechanism_. The idea is that by using a hybrid encryption scheme (combining an asymmetric and symmetric system), we can produce a highly efficient public-key system, thus getting the best of both worlds.

### Goals for the student

- Understand different security definitions for cryptosystems.
- Hands on experience programming with a variety of crypto building blocks (symmetric encryption, asymmetric encryption, hashing, MACs…).

## Collaboration

If you would like, please collaborate with a small group on this project (let’s say at most 4 people in a group). If you do collaborate with others, please **use git from the outset** so that I can see everyone’s contributions.

## The cryptosystem

### Step 1: CCA2 symmetric encryption

First, we build CCA2 symmetric encryption from the weaker assumption of CPA encryption. Let _f\_\_k_ denote our symmetric encryption with key _k_, and let _h\_\_k_′ denote our MAC with key _k_′. To encrypt a bit string _m_, we set *c* = *f\_\_k*(_m_), and set the ciphertext to the pair (_c_, *h\_\_k*′(_c_)). Decryption of a pair (_x_, *y*) first makes sure that _h\_\_k_′(_x_) = *y*; if this fails, output ⊥, otherwise decrypt _x_ and output the result.

Given that _f\_\_k_ is CPA secure and that _h\_\_k_′ is pseudorandom, it is well known that this construction is CCA2 secure. The key idea is that the MAC makes the adversary’s decryption queries useless: for any ciphertext which was not the output of the encryption oracle, the output will invariably be ⊥: To find a valid ciphertext _is_ to forge the MAC. Formal proof is left as an exercise (use any CCA2 adversary to build a CPA adversary with almost the same advantage by emulating a CCA2 _challenger_).

### Step 2: KEM to make it public-key

The idea is very simple: create a random key for the above scheme, encrypt the message you want to send, and then send it, along with a _public-key encryption of the symmetric key_. The analysis is a little tricky though. To preserve the CCA2-ness, we can’t just send a public-key encryption of the key – we need a _key encapsulation mechanism_ which has some special properties. In particular, we need our KEM to have an analogous property to CCA2 for an encryption scheme: an adversary with access to a “decapsulation” oracle (a box that outputs the key from its encapsulation) cannot differentiate between valid encapsulations (where the key corresponds to the ciphertext), and random keys. Obviously the same CCA2 rule of “you can’t decrypt the challenge” applies, but other than that, anything goes.

How to build such a thing? It turns out that all you need is a public key encryption (plain, deterministic RSA works!), a key derivation function (HMAC will do fine), and a hash function (we could use HMAC again, but we must make sure it is with a different key). Letting _K**D**F_ denote the key derivation function, _E**p**k_ the encryption (with public key _p\_\_k_) and letting _H_ denote the hash, then the KEM construction is as follows: select a random message _x_ (needs at least as much entropy as your key!) and then let *C* = (_E**p**k_(_x_), *H*(_x_)) be the encapsulation, while _K**D**F_(_x_) is the key. The “decapsulation” algorithm on input *C* = (*C_0, _C_1) simply computes \_x* = *D**p**k*(_C_0), and outputs \_K**D**F_(_x_) if _H_(_x_) = _C_1; otherwise it outputs ⊥. It isn’t too hard to prove this has the property we need. (See Dent 2003 for the details.)

### Why is the composition CCA2 secure?

There is a nice hybrid-style argument in (Cramer and Shoup 2003, chap. 7), but verifying all the details would take us a little off course. Here’s the gist though: how different could the CCA2 game be if we swapped out the encapsulated key with a totally random key for the symmetric encryption? Not very! Even if we gave the adversary the ability to run decapsulation queries, he can’t distinguish the cases (this is exactly our definition of CCA2 for a KEM). But now if the key is random, this is precisely the situation for which we’ve proved CCA2 security of the symmetric scheme. Voila.

## Details

I’ve given you a skeleton in C, but you can write the program in other languages if you want, **as long as you follow the guidelines**. Look at the [section on other languages](#other-lang) for details.

### Regarding the C skeleton

To facilitate the development, you can use [GMP](http://gmplib.org/) for the long integer arithmetic needed for RSA, and [libressl](https://www.libressl.org/) or [OpenSSL](http://www.openssl.org/) for various cryptographic primitives like hashing and symmetric encryption (they both provide a library `libcrypto` with these things).[1](#fn1)

I’ve given you a skeleton, as well as some examples that you can draw upon. The stubs that you are supposed to fill out are labeled “TODO”. Unless you have a super-compelling reason, I would recommend that you don’t change the interface.

Building blocks:

- RSA for PKE. You will implement this yourself. Note that this is the naive, deterministic (and hence not even IND-CPA secure) version. But it will work fine for our KEM.
- AES for symmetric encryption. You can get this from `libcrypto`. We’ll use it in counter mode for optimal speed during encryption. (**Question:** why is cbc mode encryption usually slower than cbc decryption?)
- HMAC for a MAC. Also available via `libcrypto`.

Be sure to read `man 4 random` at some point.

### Hints / even more details

#### What to do, and when

I’d attack this in the following order:

1.  RSA
2.  SKE (only on buffers)
3.  SKE that works on files
4.  KEM (shouldn’t be too challenging once you have the other pieces)

There are some basic tests for RSA and the memory buffer version of SKE (`ske_encrypt` / `ske_decrypt`) in the `tests/` directory, so those are good to start with. Once you have that working, implement the versions which operate on files. _Hint:_ For this, I would recommend `mmap`. Then you can just hand off the pointers from `mmap` to the simple versions and let the kernel do all the buffering work for you. (Nice, right?) Or if you are lazy, you can also just read the entire file contents into a (potentially huge) buffer. But Zoidberg will be mad at you.

![zoidberg](bad-code.jpg)

#### Extra notes on the KDF for symmetric encryption

_Note:_ for the KEM scheme, both the KDF and the hash function are public. To ensure “orthogonality” of the two, one is implemented via HMAC, but the key is public (it is hard-coded into `ske.c` – see `KDF_KEY`). Note that the KDF should be handled inside of this function:

    int ske_keyGen(SKE_KEY* K, unsigned char* entropy, size_t entLen);

If the `entropy` buffer is supplied, the KDF should be applied to it to derive the key. Thus when implementing `kem_encrypt`, you can take the encapsulated key `x` and supply that as `entropy`. Maybe something like this:

    unsigned char* x = malloc(len);
    /* ...fill x with random bytes (which fit in an RSA plaintext)... */
    SKE_KEY SK;
    ske_keyGen(&SK,x,len);
    /* ...now encrypt with SK... */

#### Basic usage (command line interface)

This is documented via the usage string (as well as by looking at the test script), but here are some examples.

Generate a 2048 bit key, and save to /tmp/testkey{,.pub}:

    ./kem-enc -b 2048 -g /tmp/testkey

Encrypt `file` with the public key and write ciphertext to `ct`:

    ./kem-enc -e -i file -o ct -k /tmp/testkey.pub

Decrypt `ct` with the private key and write plaintext to `file0`:

    ./kem-enc -d -i ct -o file0 -k /tmp/testkey

### Compiling, testing, debugging

As mentioned, there are some test programs in `tests/` for the RSA and SKE components. (You can build these via `make tests`.) For the hybrid KEM scheme, there’s a `kem-test.sh` script. Fill the `tests/data/` directory with some files, and it will check if encrypt and decrypt at least compose to be the identity on those inputs. Also, there is a make target called `debug` to add a few helpful compiler flags. (Run `make -B debug` to recompile with debugging flags enabled.)

### Other languages

If you want to do this in another language (or without the skeleton code), feel free to do so. Keep in mind that your code should speak the same language as the one described in the skeleton. That is,

- The binary file formats (for keys and ciphertext) should be the same.
- Your program should understand the same command line arguments.

Further, do not import libraries that trivialize the project (I think gpg does almost exactly this for encryption). I would prefer you to implement RSA (or whatever PKE you choose) directly from long integers, but let me know if you want to use a library for it. I will expect you to get AES and hash functions from a library (those aren’t particularly instructive to write on your own).

Lastly, please provide a Makefile along with any instructions you think would help if you don’t use the skeleton.

## Submission Procedure

- If collaborating with others, email me a link to your repository, and make sure there is a readme or similar that tells me who all is in your group. If you don’t have a link you can share (e.g., if you hosted your own git repository and did everything over ssh), just send me a archive of your project which includes the `.git/` directory containing the history.
- If lone-wolfing it, just make an archive like this:

      tar -czf p1.tgz /path/to/your/code/

  and email it to me.

Oh, and **please include “380” somewhere in the subject line** when you email me. Thank you!

# References

Cramer, Ronald, and Victor Shoup. 2003. “Design and Analysis of Practical Public-Key Encryption Schemes Secure Against Adaptive Chosen Ciphertext Attack.” _SIAM Journal on Computing_ 33 (1): 167–226.

Dent, Alex. 2003. “A Designer’s Guide to KEMs.” _Cryptography and Coding_, 133–51.

---

1.  Note that libressl/OpenSSL also contain implementations of RSA, but I want you to write this part yourself – it is more educational, and actually quite simple since “plain” RSA suffices for our application.[↩︎](#fnref1)
