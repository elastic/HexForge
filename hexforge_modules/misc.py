import ida_kernwin
import idaapi
import binascii
import re

from hexforge_modules import helper

REGEX_HEX = re.compile(r"[^0-9a-fA-F]")


class PatchMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::patch_memory"
        self.ACTION_TEXT = "patch_memory"
        self.ACTION_TOOLTIP = "patch_memory"

    # function to execute
    def _action(self) -> None:
        data = self._show()
        helper.write_bytes_to_selected(data)

    def _show(self):
        f = self.InputFormT()
        f, args = f.Compile()
        # Show form
        ok = f.Execute()
        if ok == 1:
            data_input = f.hex_data.value
            try:
                if f.Data_UTF8.checked:  # ascii data
                    data = data_input.encode()
                else:  # hex data
                    data = binascii.unhexlify(re.sub(REGEX_HEX, "", data_input))
            except binascii.Error as e:
                print(e)
                data = None
            f.Free()
            return data

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
                        Patch memory Settings

                        {FormChangeCb}
                        <Data UTF8:{Data_UTF8}>{cData_UTF8Group}>
                        <##Data :{hex_data}>
                        """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "cData_UTF8Group": F.ChkGroupControl(("Data_UTF8",)),
                    "hex_data": F.MultiLineTextControl(
                        text="", flags=F.MultiLineTextControl.TXTF_FIXEDFONT
                    ),
                },
            )

        def OnFormChange(self, fid):
            return 1


class NopMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::nop_memory"
        self.ACTION_TEXT = "nop_memory"
        self.ACTION_TOOLTIP = "nop_memory"

    def _action(self) -> None:
        self._nop_selected_bytes()

    def _nop_selected_bytes(self):
        data = helper.get_selected_bytes()
        if data is None:
            idaapi.msg("Failed to get selected bytes.\n")
            return

        # create NOP array with the size of the selection
        nop_data = bytearray(len(data))
        nop_data[:] = b"\x90" * len(data)

        # write the NOPs to the selected address range
        helper.write_bytes_to_selected(nop_data)


class CopyMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::copy_memory"
        self.ACTION_TEXT = "copy_memory"
        self.ACTION_TOOLTIP = "copy_memory"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        data = helper.get_selected_bytes()
        try:
            QApplication.clipboard().setText(binascii.hexlify(data).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError) as e:
            print(e)
            return None
