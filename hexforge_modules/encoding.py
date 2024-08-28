import ida_kernwin
import base64

from hexforge_modules import helper


class Base64Decode(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::base64"
        self.ACTION_TEXT = "base64 decode"
        self.ACTION_TOOLTIP = "base64 decode"

    # function to execute
    def _action(self) -> None:
        alphabet = self._show()
        data = helper.get_selected_bytes()
        decoded_data = base64.b64decode(data)
        decoded_data = decoded_data.ljust(len(data), b"\x00")
        helper.write_bytes_to_selected(decoded_data)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            alphabet = f.alphabet.value
            f.Free()
            return alphabet
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
                BASE64 Settings

                {FormChangeCb}
                <Alphabet          :{alphabet}>
                """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "alphabet": F.MultiLineTextControl(
                        text="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
                        flags=F.MultiLineTextControl.TXTF_FIXEDFONT,
                    ),
                },
            )

        def OnFormChange(self, fid):
            return 1
