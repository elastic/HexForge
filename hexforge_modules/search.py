import ida_bytes
import ida_funcs
import ida_kernwin
import idc

import binascii
import elasticsearch
import tlsh
import pathlib

from hexforge_modules import helper


DEFAULT_SCORE_THRESHOLD = 100


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


class GenomeModule(helper.ModuleTemplate):
    def __init__(self):
        self.ACTION_NAME = "hexforge::match_function"
        self.ACTION_TEXT = "Match Function (VectorSearch)"
        self.ACTION_TOOLTIP = "Match current function to known signatures using VectorSearch"

        home = pathlib.Path().home()
        cred_file = home / ".genome_es_credentials.txt"
        lines = cred_file.read_text().splitlines()
        es_cloud_id, es_api_key = lines[0], lines[1]
        self.es = elasticsearch.Elasticsearch(
            cloud_id=es_cloud_id,
            api_key=es_api_key,
        )

    def _action(self) -> None:
        from PyQt5.Qt import QApplication

        ea = idc.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            print("Failed to get function object")
            return

        func = ida_funcs.get_func(ea)
        func_name = idc.get_func_name(func.start_ea)
        start_ea = func.start_ea
        end_ea = func.end_ea
        func_size = end_ea - start_ea
        func_bytes = ida_bytes.get_bytes(start_ea, func_size)
        tlsh_hash = tlsh.hexdigest(func_bytes, 1)
        print(f"Function {func_name} got TLSH={tlsh_hash}, looking up...")

        vector = tlsh_hash[-64:]
        lowest_size = round(0.90 * func_size)
        highest_size = round(1.10 * func_size)

        es_query = {
            "field": "tlsh_vector",
            "query_vector": vector,
            "k": 5,
            "num_candidates": 50,
            "filter": [{"range": {"size": {"gt": lowest_size, "lt": highest_size}}}],
        }
        index_name = "genome-dataatoms-functions*"
        matches = []

        if True:
            response = self.es.search(index=index_name, body={"knn": es_query})
            hits = response.get("hits", {}).get("hits", [])
            for hit in hits:
                original_name = hit.get("_source", {}).get("name", "Unknown")
                original_tlsh = hit.get("_source", {}).get("tlsh", "Unknown")

                t1 = tlsh.Tlsh()
                t1.load(tlsh_hash)
                assert t1.valid
                t2 = tlsh.Tlsh()
                t2.load(original_tlsh)
                assert t2.valid
                diff_score = t1.diff(t2)
                if diff_score > DEFAULT_SCORE_THRESHOLD:

                    continue

                matches.append((original_name, diff_score))

        matches.sort(key=lambda x: x[1])
        print(f"Found {len(matches)} matches")
        symbol, score = matches[0]
        print(f"Best match for {func_name} is {symbol} (score={score}, threshold={DEFAULT_SCORE_THRESHOLD})")
        return
