# Python-Scripts
This repository consists of different Python scripts written for different purposes. Below is the list of scripts and their purposes:

* **vigenereDecrypt.py**: Performs Vigenere decryption with a given encrypted text. It can still decrypt even if the key or key length is unknown. For more information please run ```./vigenereDecrypt.py -h```
* **webRecon.py**: Performs web server information gathering. It only uses legitimate GET requests. Checks HTTP headers, cookies, robots.txt and home page content with regard to lists of known phrases. It can be enriched by adding items to these lists. For usage information please run ```./webRecon.py -h```
* **webFingerprinter.py**: Performs web server fingerprinting based on outcomes of 9 different tests. Tests to be used can be determined by user. For more information please run ```./webFingerprinter.py -h```
