# core-decrypt
Tool for recovering Bitcoin Core wallet passwords. Requires an OpenCL device.


Usage:

```
core-decrypt [OPTIONS] [ENCRYPTED_MASTER_KEY] [WORD FILES ..]

--list-devices	List devices then exit
--device NUM    Use device NUM
--start NUM     Specify where in the password space to start
```

### Reading the encrypted master key

Run the `walletinfo.py` script on the wallet file. The output contains the encrypted master key, number of iterations, and salt.

```
# python walletinfo.py wallet.dat
ec01bd09d2befa62ec34609fa2e19316063a9a688aef03494ab9a4d8ba67e24c414609b1ce5abb850002ecc0
```

### Recovering the password

Pass the output to the `core-decrypt` program

```
# core-decrypt.exe ec01bd09d2befa62ec34609fa2e19316063a9a688aef03494ab9a4d8ba67e24c414609b1ce5abb850002ecc0  dictionary.txt
```


The dictionaries contain one password per line. The program will try each password until it finds the correct one or exhausts the list.




More complex passwords


Multiple dictionaries can be combined together to form complex password combinations


For example, if you know the password consists of two words and a number, you might use 

```
# core-decrypt <encrypted key> words1.txt words2.txt 0_to_9.txt
```

This will try all combinations of passwords in the form,

```
[word from words1.txt][word from words2.txt][number]
```

### Sample wallets
There are some sample wallets for testing. The file name of the wallet is the password.

TODO List:

* Multi-GPU support
* Password rules
* Allow more performance tuning by user
* Better word lists