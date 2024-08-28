import binascii
import ida_kernwin
import re

from Crypto.Cipher import AES as CryptoAES
from Crypto.Cipher import ARC4 as CryptoARC4
from Crypto.Cipher import ChaCha20 as CryptoChaCha20
from hexforge_modules import helper

REGEX_HEX = re.compile(r"[^0-9a-fA-F]")


class ChaCha20(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::ChaCha20"
        self.ACTION_TEXT = "ChaCha20 decrypt"
        self.ACTION_TOOLTIP = "ChaCha20 decrypt"

    # function to execute
    def _action(self) -> None:
        key, nonce = self._show()
        encrypted_data = helper.get_selected_bytes()
        if not encrypted_data or not key or not nonce:
            return None
        cipher = CryptoChaCha20.new(key=key, nonce=nonce)
        decrypted = cipher.decrypt(encrypted_data)
        helper.write_bytes_to_selected(decrypted)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            try:
                chacha20_key_input = f.chacha20_key.value
                chacha20_nonce_input = f.chacha20_nonce.value
                if f.Chacha20Key_UTF8.checked:  # ascii data
                    chacha20_key_input = chacha20_key_input.encode()
                else:  # hex data
                    chacha20_key_input = binascii.unhexlify(
                        re.sub(REGEX_HEX, "", chacha20_key_input)
                    )

                if f.Chacha20Key_UTF8.checked:  # ascii data
                    chacha20_nonce_input = chacha20_nonce_input.encode()
                else:  # hex data
                    chacha20_nonce_input = binascii.unhexlify(
                        re.sub(REGEX_HEX, "", chacha20_nonce_input)
                    )
            except binascii.Error as e:
                print(e)
                chacha20_key_input = None
                chacha20_nonce_input = None
            f.Free()
            return chacha20_key_input, chacha20_nonce_input
        else:
            f.Free()
            return None

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                CHACHA20 Settings

                {FormChangeCb}
                <CHACHA20 key UTF8:{Chacha20Key_UTF8}>{cChacha20Key_UTF8Group}> | <##  :{chacha20_key}>
                <CHACHA20 nonce UTF8:{Chacha20Nonce_UTF8}>{cChacha20Nonce_UTF8Group}> | <##  :{chacha20_nonce}>
                """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cChacha20Key_UTF8Group": F.ChkGroupControl(("Chacha20Key_UTF8",)),
                    "cChacha20Nonce_UTF8Group": F.ChkGroupControl(
                        ("Chacha20Nonce_UTF8",)
                    ),
                    "chacha20_key": F.StringInput(),
                    "chacha20_nonce": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1


class Aes(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::AES"
        self.ACTION_TEXT = "AES decrypt"
        self.ACTION_TOOLTIP = "AES decrypt"

    # function to execute
    def _action(self) -> None:
        aes_mods_dict = {"CBC": CryptoAES.MODE_CBC, "ECB": CryptoAES.MODE_ECB}
        aes_key, aes_iv, aes_mod = self._show(
            [item for item in list(aes_mods_dict.keys())]
        )
        encrypted_data = helper.get_selected_bytes()

        if aes_mods_dict[aes_mod] == CryptoAES.MODE_CBC:
            cipher = CryptoAES.new(aes_key, aes_mods_dict[aes_mod], aes_iv)
        elif aes_mods_dict[aes_mod] == CryptoAES.MODE_ECB:
            cipher = CryptoAES.new(aes_key, aes_mods_dict[aes_mod])

        if not encrypted_data or not aes_key or not aes_iv:
            return None

        decrypted_data = cipher.decrypt(encrypted_data)
        helper.write_bytes_to_selected(decrypted_data)

    def _show(self, aes_mods_list):
        f = self.InputFormT(aes_mods_list)
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            try:
                aes_key_input = f.aes_key.value
                aes_iv_input = f.aes_iv.value

                if f.AesKey_UTF8.checked:  # ascii data
                    aes_key = aes_key_input.encode()
                else:  # hex data
                    aes_key = binascii.unhexlify(re.sub(REGEX_HEX, "", aes_key_input))

                if f.AesIv_UTF8.checked:  # ascii data
                    aes_iv = aes_iv_input.encode()
                else:  # hex data
                    aes_iv = binascii.unhexlify(re.sub(REGEX_HEX, "", aes_iv_input))
            except binascii.Error as e:
                print(e)
                aes_key = None
                aes_iv = None
            mod_chooser = f.cModChooser[f.cModChooser.value]

            f.Free()
            return aes_key, aes_iv, mod_chooser
        else:
            f.Free()
            return None

    class InputFormT(ida_kernwin.Form):
        class mod_chooser_t(ida_kernwin.Choose):
            """
            A simple chooser to be used as an embedded chooser
            """

            def __init__(self, aes_mods_list):
                ida_kernwin.Choose.__init__(
                    self,
                    "",
                    [
                        ["AES mod", 9],
                        ["", 9],
                    ],
                    flags=0,
                    embedded=True,
                    width=30,
                    height=6,
                )
                self.items = aes_mods_list
                self.icon = None

            def OnGetLine(self, n):
                return self.items[n]

            def OnGetSize(self):
                return len(self.items)

        def __init__(self, aes_mods_list):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                AES Settings

                {FormChangeCb}
                <AES KEY UTF8:{AesKey_UTF8}>{cAesKey_UTF8Group}> | <##  :{aes_key}>
                <AES IV UTF8:{AesIv_UTF8}>{cAesIv_UTF8Group}>  | <##  :{aes_iv}>
                <##AES mod:{cModChooser}>
                """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cAesKey_UTF8Group": F.ChkGroupControl(("AesKey_UTF8",)),
                    "cAesIv_UTF8Group": F.ChkGroupControl(("AesIv_UTF8",)),
                    "aes_key": F.StringInput(),
                    "aes_iv": F.StringInput(),
                    "cModChooser": F.DropdownListControl(
                        items=aes_mods_list, readonly=True, selval=0
                    ),
                },
            )

        def OnFormChange(self, fid):
            return 1


class Xor(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::XOR"
        self.ACTION_TEXT = "XOR decrypt"
        self.ACTION_TOOLTIP = "XOR decrypt"

    # function to execute
    def _action(self) -> None:
        xor_value = self._show()
        data = helper.get_selected_bytes()
        if not data or not xor_value:
            return None
        for i in range(0, len(data)):
            data[i] ^= xor_value[i % len(xor_value)]
        helper.write_bytes_to_selected(data)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            try:
                xor_key_input = f.xor_key.value
                if f.XorKey_UTF8.checked:  # ascii data
                    xor_key = xor_key_input.encode()
                else:  # hex data
                    xor_key = binascii.unhexlify(re.sub(REGEX_HEX, "", xor_key_input))
            except binascii.Error as e:
                print(e)
                xor_key = None
            f.Free()
            return xor_key
        else:
            f.Free()
            return None

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                XOR Settings

                {FormChangeCb}
                <XOR key UTF8:{XorKey_UTF8}>{cXorKey_UTF8Group}> | <##  :{xor_key}>
                """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cXorKey_UTF8Group": F.ChkGroupControl(("XorKey_UTF8",)),
                    "xor_key": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1


class Rc4((helper.ModuleTemplate)):
    def __init__(self):
        self.ACTION_NAME = "hexforge::RC4"
        self.ACTION_TEXT = "RC4 decrypt"
        self.ACTION_TOOLTIP = "RC4 decrypt"

    # function to execute
    def _action(self) -> None:
        rc4_key = self._show()
        encrypted_data = helper.get_selected_bytes()
        if not encrypted_data or not rc4_key:
            return None
        cipher = CryptoARC4.new(rc4_key)
        decrypted_data = cipher.encrypt(encrypted_data)
        helper.write_bytes_to_selected(decrypted_data)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            try:
                rc4_key_input = f.rc4_key.value
                if f.Rc4Key_UTF8.checked:  # ascii data
                    rc4_key = rc4_key_input.encode()
                else:  # hex data
                    rc4_key = binascii.unhexlify(re.sub(REGEX_HEX, "", rc4_key_input))
            except binascii.Error as e:
                print(e)
                rc4_key = None
            f.Free()
            return rc4_key
        else:
            f.Free()
            return None

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                RC4 Settings

                {FormChangeCb}
                <RC4 key UTF8:{Rc4Key_UTF8}>{cRc4Key_UTF8Group}> | <##  :{rc4_key}>
                """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cRc4Key_UTF8Group": F.ChkGroupControl(("Rc4Key_UTF8",)),
                    "rc4_key": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1
