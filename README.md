## HexForge IDA plugin
This IDA plugin extends the functionality of the assembly and hex view. With this plugin, you can conveniently decode/decrypt/alter data directly from the IDA Pro interface. The following actions include:
- Copying raw hex from IDA's disassembly or hex view
- Patching or nopping bytes from memory or statically
- Quickly use popular crypto/encoding algorithms for decryption
  - AES
  - ChaCha20
  - RC4
  - XOR
  - Base64

## How to install
Install the required libraries via `pip install -r requirements.txt`, then copy the latest version of `hexforge_module` and `HexForge.py` into your IDA Pro plugins directory.


## How to use
Select the data in IDA hex view or disassembly view and right click to get the menu



![image](images/hexforge.png)


### How to add a module
This section will help you understand how to add new modules to the `hexforge_modules` package. By following these steps, you can create custom modules that integrate seamlessly with the Hexforge framework.

- Start by creating a new Python class inside the hexforge_modules package. This class will represent your module. The class should be named appropriately to reflect its purpose.
- Your class must inherit from the `helper.ModuleTemplate` class.
- The `_action` method is where you define the main logic of your module. This could be encryption, decryption, compression, or any other action your module is designed to perform.
- If your module requires user input, you should create a GUI interface using the InputFormT class. This form will be presented to the user when your module is invoked.

You can follow the example provided below for XOR decryption:

https://github.com/elastic/HexForge/blob/ac8d118d30f9c784514a63caf2e3fd391b378ffb/hexforge_modules/crypto.py#L202


## License

Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use these artifacts except in compliance with the Elastic License 2.0

Contributors must sign a [Contributor License Agreement](https://www.elastic.co/contributor-agreement) before contributing code to any Elastic repositories.
