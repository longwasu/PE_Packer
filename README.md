# PE Packer
This is packer for portable executable file format in Windows.(https://attack.mitre.org/techniques/T1027/002/)

Only work with 32 bit executable.

The algorithm is really simple, it just use API RtlCompressionBuffer() to compress the PE file need to be packed.


## Example 



