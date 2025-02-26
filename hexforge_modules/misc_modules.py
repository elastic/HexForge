import ida_kernwin
import idaapi
import idc
import binascii
import re

from hexforge_modules import helper

REGEX_HEX = re.compile(r"[^0-9a-fA-F]")


class PatchMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::patch_memory"
        self.ACTION_TEXT = "patch memory"
        self.ACTION_TOOLTIP = "patch memory"

    # function to execute
    def _action(self) -> None:
        data = self._show()
        helper.write_bytes_to_selected(data)

    def _show(self):
        f = self.InputFormT()
        f, _ = f.Compile()
        # Show form
        f.Execute()
        data = None
        try:
            data_input = f.hex_data.value
            if f.Data_UTF8.checked:  # ascii data
                data = data_input.encode()
            else:  # hex data
                data = binascii.unhexlify(re.sub(REGEX_HEX, "", data_input))
        except binascii.Error as e:
            print(e)
        f.Free()
        return data


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
        self.ACTION_TEXT = "nop memory"
        self.ACTION_TOOLTIP = "nop memory"

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
        self.ACTION_TEXT = "copy memory"
        self.ACTION_TOOLTIP = "copy memory"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        data = helper.get_selected_bytes()
        try:
            QApplication.clipboard().setText(binascii.hexlify(data).decode("utf-8"))
        except (binascii.Error, UnicodeDecodeError) as e:
            print(e)
            return None


class DumpMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::dump_memory"
        self.ACTION_TEXT = "dump memory"
        self.ACTION_TOOLTIP = "dump memory"

    # function to execute
    def _action(self) -> None:
        result = self._show()
        if result:
            start_addr, end_addr, filepath = result
            self.dump_memory_to_file(start_addr, end_addr, filepath)

    def _show(self):
        f = self.InputFormT()
        f, _ = f.Compile()
        # Show form
        f.Execute()
        start_addr = None
        end_addr = None
        filepath = None
        try:
            start_addr = int(f.start_addr.value, 16)
            end_addr = int(f.end_addr.value, 16)
            filepath = f.filepath.value
        except ValueError as e:
            print(e)
        f.Free()
        return start_addr, end_addr, filepath

    def dump_memory_to_file(self, start_addr, end_addr, filepath):
        size = end_addr - start_addr
        data = idaapi.get_bytes(start_addr, size)
        if data:
            with open(filepath, "wb") as f:
                f.write(data)
            print(f"Memory dumped to {filepath}")
        else:
            print("Failed to read memory")

    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                        Dump Memory

                        {FormChangeCb}
                        <Start Address    :{start_addr}>
                        <End Address      :{end_addr}>
                        <Filepath         :{filepath}>
                        """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "start_addr": F.StringInput(),
                    "end_addr": F.StringInput(),
                    "filepath": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1


class GetRVA(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::get_RVA"
        self.ACTION_TEXT = "get RVA"
        self.ACTION_TOOLTIP = "get RVA"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        image_base = idaapi.get_imagebase()
        current_addr = idc.get_screen_ea()

        if current_addr != idc.BADADDR:
            rva = current_addr - image_base
            print(f"Image Base: 0x{image_base:X}")
            print(f"Current Address: 0x{current_addr:X}")
            print(f"RVA: 0x{rva:X}")

            try:
                QApplication.clipboard().setText(f"0x{rva:X}")
            except (binascii.Error, UnicodeDecodeError) as e:
                print(e)
                return None
        else:
            print("No valid address selected!")


class GetCurrentAddress(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::get_current_address"
        self.ACTION_TEXT = "get current address"
        self.ACTION_TOOLTIP = "get current address"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        image_base = idaapi.get_imagebase()
        current_addr = idc.get_screen_ea()

        if current_addr != idc.BADADDR:
            print(f"Image Base: 0x{image_base:X}")
            print(f"Current Address: 0x{current_addr:X}")

            try:
                QApplication.clipboard().setText(f"0x{current_addr:X}")
            except (binascii.Error, UnicodeDecodeError) as e:
                print(e)
                return None
        else:
            print("No valid address selected!")


class GetFileOffset(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::get_file_offset"
        self.ACTION_TEXT = "get file offset address"
        self.ACTION_TOOLTIP = "get file offset address"

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        current_ea = idc.get_screen_ea()

        # Map the VA to the corresponding file offset
        file_offset = idaapi.get_fileregion_offset(current_ea)

        if file_offset != -1:
            print(f"Current Address: 0x{current_ea:X}")
            print(f"File Offset: 0x{file_offset:X}")

            try:
                QApplication.clipboard().setText(f"0x{file_offset:X}")
            except (binascii.Error, UnicodeDecodeError) as e:
                print(e)
                return None
        else:
            print("Failed to compute file offset.")


class SetMemory(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::set_memory"
        self.ACTION_TEXT = "set memory"
        self.ACTION_TOOLTIP = "set memory"

    # function to execute
    def _action(self) -> None:
        value = self._show()
        data = helper.get_selected_bytes()
        val_data = bytearray(len(data))
        val_data[:] = value * len(data)
        helper.write_bytes_to_selected(val_data)

    def _show(self):
        f = self.InputFormT()
        f, _ = f.Compile()
        # Show form
        f.Execute()
        value = None
        try:
            value_input = f.Value.value
            value = binascii.unhexlify(re.sub(REGEX_HEX, "", value_input))
        except binascii.Error as e:
            print(e)
        f.Free()
        return value


    class InputFormT(ida_kernwin.Form):
        def __init__(self):
            self.__n = 0
            F = ida_kernwin.Form
            F.__init__(
                self,
                r"""BUTTON YES* Ok
                        Set memory Settings

                        {FormChangeCb}
                        <##1-byte value :{Value}>
                        """,
                {
                    "FormChangeCb": F.FormChangeCb(self.OnFormChange),
                    "Value": F.StringInput(),
                },
            )

        def OnFormChange(self, fid):
            return 1
