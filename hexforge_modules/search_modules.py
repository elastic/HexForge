import ida_kernwin
import idaapi
import binascii
import re

from hexforge_modules import helper


class SearchGoogle(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::search_google_string"
        self.ACTION_TEXT = "search string in Google"
        self.ACTION_TOOLTIP = "search string in Google"

    def _action(self) -> None:

        data = helper.get_highlighted_string_from_decompiler()
        try:
            formatted_url = f"https://www.google.com/search?q={data}"
            ida_kernwin.open_url(formatted_url)
            
        except Exception as e:
            print(e)
            return None
        
class SearchGitHub(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::search_github"
        self.ACTION_TEXT = "search string in GitHub"
        self.ACTION_TOOLTIP = "search string in GitHub"

    def _action(self) -> None:

        data = helper.get_highlighted_string_from_decompiler()
        try:
            formatted_url = f"https://github.com/search?q={data}&type=code"
            ida_kernwin.open_url(formatted_url)
            
        except Exception as e:
            print(e)
            return None

class SearchGrepApp(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::search_grepapp_string"
        self.ACTION_TEXT = "search string in Grep.app"
        self.ACTION_TOOLTIP = "search string in Grep.app"

    def _action(self) -> None:

        data = helper.get_highlighted_string_from_decompiler()
        try:
            formatted_url = f"https://grep.app/search?q={data}"
            ida_kernwin.open_url(formatted_url)
            
        except Exception as e:
            print(e)
            return None
        
class SearchVirustotalBytes(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::search_virustotal_bytes"
        self.ACTION_TEXT = "search bytes in VirusTotal"
        self.ACTION_TOOLTIP = "search bytes in VirusTotal"

    def _action(self) -> None:

        data = helper.get_selected_bytes()
        try:
            hex_data = binascii.hexlify(data).decode('utf-8')
            formatted_url = f"https://www.virustotal.com/gui/search/content%253A%2520%257B{hex_data}%257D"
            ida_kernwin.open_url(formatted_url)
            
        except (binascii.Error, UnicodeDecodeError) as e:
            print(e)
            return None
        
class SearchVirustotalString(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::search_virustotal_string"
        self.ACTION_TEXT = "search string in VirusTotal"
        self.ACTION_TOOLTIP = "search string in VirusTotal"

    def _action(self) -> None:

        data = helper.get_highlighted_string_from_decompiler()
        try:
            formatted_url = f"https://www.virustotal.com/gui/search/content%253A%2520{data}"
            ida_kernwin.open_url(formatted_url)
            
        except Exception as e:
            print(e)
            return None


