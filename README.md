README
======

# stricat 1.20140429 by Markku-Juhani O. Saarinen <mjos@iki.fi>

1. Introduction and License
2. Download, Compile, and Test
3. Hashing
4. Keying
5. Encryption and Decryption
6. Networking and File Transfer
7. Binding a Shell or Command

## 1. Introduction

This is a quick tutorial to the StriCat (pronounced "stree cat")
multi-use cryptographic tool, which can be used to hash, encrypt, and
decrypt files and to establish secure communication links over TCP.
StriCat has been designed to be self-contained, portable, and extremely
lightweight (only few thousand lines). StriCat is also able to perform
GOST R 34.11-2012 "Streebog" - compliant hashing.

StriCat is based on the STRIBOB cryptographic permutation (which is
a CAESAR candidate) and the BLINKER sponge mode of operation
presented at CT-RSA '14. The three documents are:

1.	M.-J. O. Saarinen: "The STRIBOBr1 Authenticated Encryption
	Algorithm" A first round CAESAR submission. March 2014.
	http://stribob.com
2.	M.-J. O. Saarinen: "STRIBOB: Authenticated Encryption from GOST
	R 34.11-2012 LPS Permutation (Extended Abstract)" CTCrypt 2014, 05-06
	June 2014, Moscow, Russia. http://eprint.iacr.org/2014/271.
3.	M.-J. O. Saarinen: "Beyond Modes: Building a Secure Record
	Protocol from a Cryptographic Sponge Permutation" CT-RSA 2014, LNCS
	8366, pp. 270-285, Springer 2014. http://eprint.iacr.org/2013/772.

The padding rules have undergone small changes from, and StriCat
implements a superset of features given in the STRIBOBr1 AEAD
submission to the CAESAR Competition, which is available from the
STRIBOB website http://www.stribob.com. Alternative and optimized
implementations can also be found on that site.

The protocol can run on arbitrary network interfaces in addition to TCP
and we have implemented it even on MSP430 ultra-low power embedded
microcontroller chips.

Special thanks to NTNU and Kudelski Security for sponsoring
this work (or its predecessors). See small print in LICENSE file!


## 2. Download, Compile, and Test

Versions of StriCat are available from the distribution directory
http://www.stribob.com/dist. Versions are numbered by dates:
stricat-yyyymmddhhmmss.tgz.

On any modern Linux platform you should be able to extract and compile
the system with:
```
 $ tar xfvz stricat-yyyymmddhhmmss.tgz
 $ cd stricat
 $ make
```
This will create the "stricat" executable which can be copied to a
suitable location. If you're compiling on a new platform you may
quickly test the integrity of the STRIBOBr1 transform with:
```
 $ ./stricat -t
 Compiled on Mar 27 2014 09:54:58
 stribob_selftest() == 0
```
Zero implies success. There's also some online help available:
```
 $ ./stricat -h
 stricat: STRIBOB / STREEBOG Cryptographic Tool.
 (c) 2013-4 Markku-Juhani O. Saarinen <mjos@iki.fi>. See LICENSE.

 stricat [OPTION].. [FILE]..
  -h			This help text
  -t			Quick self-test and version information

 Shared secret key (use twice to verify):
  -q			Prompt for key
  -f <file>  Use file as a key
  -k <key>	Specify key on command line

 Files:
  -e			Encrypt stdin or files (add .sb1 suffix)
  -d			Decrypt stdin or files (must have .sb1 suffix)
  -s			Hash stdin or files in STRIBOB BNLK mode (optionally keyed)
  -g			GOST R 34.11-2012 unkeyed Streebog hash with 256-bit output
  -G			GOST R 34.11-2012 unkeyed Streebog hash with 512-bit output
```

## 3. Hashing

When invoked with the "-s", "-g", or "-G" flags, stricat behaves in a
similar fashion to "md5sum" and "sha1sum" tools. Here "-s" indicates
the (optionally keyed) StriBob hash/mac, and "-g" and "-G" options
result in GOST34.11-2012 Streebog - compliant hashes of 256 or 512
bits, respectively.  Streebog hashes cannot be keyed but StriBob hashes 
can be (StriBob works as a MAC perfectly well). If there are no
additional parameters, data is simply taken in from stdin and hashed to
the output.
```
 $ echo "Hello" | ./stricat -s
 086927f0bdf5f0cb7e27c760c07e198d
 $ echo "Hello" | ./stricat -g
 ed4bb0870f96417e2b7f8cd19a98f470467fc356ac160aeee0592ae69f912930
 $ echo "Hello" | ./stricat -G
 63232f5ca2c70b3367d25923ac0b81f720db9b5db1f17a717d0efb9d02122c8387d8a08
 063e696cddfaa373497912299d6119dbace3a0024ce61250c3fed9037
```
You may also invoke the hash options it directly on multiple files:
```
 $ ./stricat -s *.h da99af5d429f6f194d7deef0d8f838a4 blnk.h
 5e5e27bbe8ca0b2886ccbec10b2c7952  iocom.h
 e439b915e3e76ae5561a30fbd3f0cb70  streebog.h
 790f857e4e98865edc45ae4716b8b8be  stribob.h
```
Hash/MAC outputs are always 128 bits for StriBob, and 256 (-g) or 512
(-G) bits for Streebog.


## 4. Keying

All operations except hashing require a single symmetric shared key,
which is used for both confidentiality and integrity protection. You
can also specify a key for hashing; the same key will be required to
verify the hash.

There are three ways to supply keys, and you can use any of them in any
order, as many times you wish, but all of the supplied keys must be
equal!

```
-q
```
Prompt for a password. Invoke twice with -qq and you will be asked to
verify the given password. This is recommended for encryption
operations.

```
-k key
```
Will take the key as argument on command line.

```
-f path
```
Reads the password from a file contained in argument. The entire
contents of the file be used in binary form, so be careful about line
feeds. You may also use special files such as pipes or /dev/tty.

**Example**. This keyed hashing operation uses all three key input methods:
```
 $ echo "Hello" | ./stricat -q -k "" -f /dev/null -q -s
 Secret key:
 Verify key:
 bcb7de5552d4077879ba074077119153 -
```
You will be first prompted to enter a Secret Key -- just press enter.
The operation will fail otherwise due to empty password supplied by -k
and -f. However you will be prompted again to verify the empty given
password.


## 5. Encryption and Decryption

When invoked without file names, the operation is from standard input
to standard output. Note that a chunked file format is used here (chunk
lengths are Associated Authenticated Data or AAD) and hence the output
is not directly compatible with the CAESAR submission.

```
-e
```
 Encrypt a stream or files.

```
-d
```
 Decrypt a stream or files.

The ".sb1" suffix is added to encrypted files and expected from files
to be decryption.

stricat is capable of encrypting and decrypting streams of arbitrary
length as the operation is performed on individually protected chunks.
Also there is strong integrity protection against truncation and other
attacks, which leads to some message expansion. No other attributes
except the contents of the file are protected; you should use tools
such as "tar" to store those attributes.

To encrypt the binary executable itself:
```
 $ ./stricat -e -k testkey stricat
 $ ls -l stricat*
 -rwxrwxr-x 1 mjos mjos 53442 Apr 28 19:03 stricat
 -rw-rw-r-- 1 mjos mjos 53482 Apr 28 19:30 stricat.sb1
```
We will decrypt the ciphertext file to stricat.2 using streams:
```
 $ ./stricat -d -k testkey <stricat.sb1 >stricat.2
```
We can now verify that the two plaintext files are equivalent by
hashing them:
```
 $ ./stricat -s stricat stricat.2
 9e22df3994d34335f92b2f9a096423ff stricat
 9e22df3994d34335f92b2f9a096423ff stricat.2
```
Your compilation of the binary will of course have a different hash.


## 6. Networking and File Transfer

The networking side of stricat has been modeled after the "netcat"
tool, with the difference that stricat uses and a rather elaborate (yet
fast) randomized mutual authentication scheme to establish session keys
for confidentiality and integrity protection.

```
-p port
```
 Specify a TCP port. By default port 48879 is used.

```
-l
```
 Listen mode. Wait for an incoming connection at the specified port,
 perform handshake and authentication, and then direct standard input
 and output through the established cryptographic channel.

```
-c hostname
```
 Connect to the internet host given as argument (e.g. localhost) and
 perform handshake and authentication. Standard input and output are
 forwarded to the encrypted channel.

The same keying options are available as for file encryption and
decryption.

In it's most basic form we can have a little chat over the channel. On
first terminal, set up listener at standard port 48879 with shared
secret "password":
```
 bobby$ ./stricat -k password -l
```
On second terminal, we can connect to the listener at "bobby", port
48879:
```
 alice$ ./stricat -q -c bobby
 Secret key:
```
You must enter the correct "password" in the prompt for the
authentication to success. After this you may write lines of text to
either terminal and it will pop up in the other (the standard streams
are line buffered by default).

We may also transmit files using streams. This command issued on bobby
will wait for connection at port 12345:
```
 bobby$ ./stricat -k keykey -p 12345 -l > dump.dat
```
Upon execution the command
```
 alice$ ./stricat -k keykey -p 12345 -c bobby < dump.dat
```
The file "dump.dat" will be copied to destination.


## 7. Binding a Shell or Command

A simple shell can be bound at either end of the connection simply by
specifying the shell (or any other interactive command) as a singular
argument. You must pass arguments to the command inside parenthesis so
that they are not confused with arguments to stricat.

This starts a "poor man's sshd" for a single incoming session at port
48879 with shared secret "keu":
```
 bobby$ ./stricat -k keu -l "/bin/bash -i"
```
To connect:
```
 alice$ ./stricat -k keu -c bobby
```
Upon connection one may now use the shell at "bobby". Since i/o is line
buffered and there is no tty handshake, the interaction is somewhat
limited and there is some latency. Use "exit" to exit the session.

Reverse bind shell as easy; we first start the listener without
arguments:
```
 bobby$ ./stricat -k keu -l
```
And then invoke on target:
```
 alice$ ./stricat -k keu -c bobby "/bin/bash -i"
```
And target's shell will pop up at bobby.
