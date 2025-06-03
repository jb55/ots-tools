
# ots-tool

Some tools for working with opentimestamps formats. Right now there is a tool
for parsing the opentimestamps serialized proof format.

## Examples

### Printing

```
$ ./otsprint file.ots

version 1
file_hash sha256 fb797ce014e3d782f0df30074de621f3577e30053b9a7e6e44cdc3ce572ffbbf
append 95cd85698021fa4425b4eb3c5f71e1c5
sha256
|
\--> append 2bbc375cfb9e3c38
|    sha256
|    append d0768aee997921e2809d8b13e9393595
|    sha256
|    prepend 17ef710b8f83389e27f7b4d4a6b9ab9c37c5b9c5b03c952c81803192827f9fcb
|    sha256
|    append 94bbc471fc065162cb616b241e8a093c6d9a5dc611eaa0b8a98e2d914990220d
|    sha256
|    prepend 683f0221
|    append 0ac198058f3d06ed
|    attestation calendar https://alice.btc.calendar.opentimestamps.org
|
\--> append 4cef1eeed5499a43009f02d71daf1ad2
|    sha256
|    prepend 683f0220
|    append 2a8f10f27b04c2aa
|    attestation calendar https://btc.calendar.catallaxy.com
|
\--> append 853acd964bf58d33
|    sha256
|    append 71817fafb20ee5c53bc09e184c8a262b
|    sha256
|    prepend 683f0220
|    append c75dc50e76f12cc0
|    attestation calendar https://bob.btc.calendar.opentimestamps.org
append a2febf4ae48590466fac3e1270c0a66e
sha256
prepend 349be34421b6acffd7a9a1d6fd5590fe21cb0f420af62c92d429111bb3fc6ae7
sha256
append 9ddbdd2979b6510bef0cf2616b45624b7252b83f0091b5631d22fe9b84884b9c
sha256
prepend 683f0221
append 5f7d7b98e9e065fb
attestation calendar https://finney.calendar.eternitywall.com
```


### Minimizing

```
$ ./otsmini file.ots

CQWAyoiuwY7dmUscDrEcphi1mzxL35CUmoebUh3brGwyNM8YZThQbxk7hE7Mxss7sPX1yXiYh48dYD8ELGUJWU9mWTm8tqagykBXYfV87Jg8iLtL7y1tJECWrGiFWe1QJ7cX9D1nH8o9ZiyEyob2yhdXHNyzfmrfrmrjqz3e1Nxgrnp
```

```
$ ./otsmini file.ots | ./otsmini -d | ./otsprint

version 1
file_hash sha256 fb797ce014e3d782f0df30074de621f3577e30053b9a7e6e44cdc3ce572ffbbf
append 95cd85698021fa4425b4eb3c5f71e1c5
sha256
append 4cef1eeed5499a43009f02d71daf1ad2
sha256
prepend 683f0220
append 2a8f10f27b04c2aa
attestation calendar https://btc.calendar.catallaxy.com
```
